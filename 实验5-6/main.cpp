#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <array>
#include <random>
#include <chrono>

using namespace std;
using namespace seal;

// ==================== 常量定义 ====================
constexpr size_t kInputRows = 4;
constexpr size_t kInputCols = 4;
constexpr size_t kKernelRows = 3;
constexpr size_t kKernelCols = 3;
constexpr size_t kOutputRows = 2;
constexpr size_t kOutputCols = 2;
constexpr size_t kInputSize = kInputRows * kInputCols;
constexpr size_t kKernelSize = kKernelRows * kKernelCols;
constexpr size_t kOutputSize = kOutputRows * kOutputCols;
constexpr double kTolerance = 1e-4;

const array<int, kKernelSize> kOffsets = { 0, 1, 2, 4, 5, 6, 8, 9, 10 };
const array<size_t, kOutputSize> kOutputSlots = { 0, 1, 4, 5 };

// ==================== 辅助函数 ====================

void print_matrix(const vector<double>& mat, int rows, int cols, const string& title = "") {
    if (!title.empty()) cout << title << endl;
    for (int i = 0; i < rows; i++) {
        cout << "[";
        for (int j = 0; j < cols; j++) {
            cout << setw(12) << setprecision(6) << mat[i * cols + j];
            if (j < cols - 1) cout << ", ";
        }
        cout << " ]" << endl;
    }
    cout << endl;
}

vector<double> plaintext_correlation(
    const vector<double>& input,
    const vector<double>& kernel) {

    vector<double> result(kOutputSize, 0.0);

    for (size_t out_r = 0; out_r < kOutputRows; out_r++) {
        for (size_t out_c = 0; out_c < kOutputCols; out_c++) {
            double sum = 0.0;
            for (size_t kr = 0; kr < kKernelRows; kr++) {
                for (size_t kc = 0; kc < kKernelCols; kc++) {
                    size_t input_idx = (out_r + kr) * kInputCols + (out_c + kc);
                    size_t kernel_idx = kr * kKernelCols + kc;
                    sum += input[input_idx] * kernel[kernel_idx];
                }
            }
            result[out_r * kOutputCols + out_c] = sum;
        }
    }
    return result;
}

vector<double> extract_output(const vector<double>& slots) {
    vector<double> output(kOutputSize);
    for (size_t i = 0; i < kOutputSize; i++) {
        output[i] = slots[kOutputSlots[i]];
    }
    return output;
}

double max_abs_error(const vector<double>& a, const vector<double>& b) {
    double max_err = 0.0;
    for (size_t i = 0; i < a.size(); i++) {
        max_err = max(max_err, fabs(a[i] - b[i]));
    }
    return max_err;
}

// ==================== 加密输入打包 ====================

Ciphertext encrypt_input(
    const vector<double>& input,
    CKKSEncoder& encoder,
    Encryptor& encryptor,
    double scale) {

    vector<double> packed(encoder.slot_count(), 0.0);
    copy(input.begin(), input.end(), packed.begin());

    Plaintext plain;
    encoder.encode(packed, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    return encrypted;
}

// ==================== 带计数的旋转 ====================

void counted_rotate(
    Evaluator& evaluator,
    const Ciphertext& source,
    int steps,
    const GaloisKeys& galois_keys,
    Ciphertext& destination,
    size_t& counter) {

    evaluator.rotate_vector(source, steps, galois_keys, destination);
    counter++;
}

// ==================== 解密与输出 ====================

vector<double> decrypt_output(
    const Ciphertext& ciphertext,
    CKKSEncoder& encoder,
    Decryptor& decryptor) {

    Plaintext plain;
    decryptor.decrypt(ciphertext, plain);

    vector<double> decoded;
    encoder.decode(plain, decoded);

    return extract_output(decoded);
}

// ==================== 作业5: 直接密文卷积 ====================

struct ConvolutionResult {
    Ciphertext ciphertext;
    size_t rotations;
};

ConvolutionResult direct_convolution(
    const Ciphertext& encrypted_input,
    const vector<double>& kernel,
    const vector<Plaintext>& direct_masks,
    Evaluator& evaluator,
    const GaloisKeys& galois_keys,
    const RelinKeys& relin_keys,
    int rotation_sign) {

    ConvolutionResult result;
    result.rotations = 0;
    bool initialized = false;

    for (size_t i = 0; i < kKernelSize; i++) {
        Ciphertext term;

        if (kOffsets[i] == 0) {
            term = encrypted_input;
        }
        else {
            counted_rotate(
                evaluator,
                encrypted_input,
                rotation_sign * kOffsets[i],
                galois_keys,
                term,
                result.rotations);
        }

        evaluator.multiply_plain_inplace(term, direct_masks[i]);
        evaluator.relinearize_inplace(term, relin_keys);

        if (!initialized) {
            result.ciphertext = move(term);
            initialized = true;
        }
        else {
            evaluator.add_inplace(result.ciphertext, term);
        }
    }

    evaluator.rescale_to_next_inplace(result.ciphertext);
    return result;
}

// ==================== 作业6: BSGS密文卷积 ====================

ConvolutionResult bsgs_convolution(
    const Ciphertext& encrypted_input,
    const vector<array<Plaintext, kKernelCols>>& bsgs_masks,
    Evaluator& evaluator,
    const GaloisKeys& galois_keys,
    const RelinKeys& relin_keys,
    int rotation_sign) {

    ConvolutionResult result;
    result.rotations = 0;

    array<Ciphertext, kKernelCols> baby;
    baby[0] = encrypted_input;

    counted_rotate(evaluator, encrypted_input, rotation_sign * 1, galois_keys, baby[1], result.rotations);
    counted_rotate(evaluator, encrypted_input, rotation_sign * 2, galois_keys, baby[2], result.rotations);

    array<Ciphertext, kKernelRows> groups;

    for (size_t a = 0; a < kKernelRows; a++) {
        bool initialized = false;
        for (size_t b = 0; b < kKernelCols; b++) {
            Ciphertext term = baby[b];
            evaluator.multiply_plain_inplace(term, bsgs_masks[a][b]);
            evaluator.relinearize_inplace(term, relin_keys);

            if (!initialized) {
                groups[a] = move(term);
                initialized = true;
            }
            else {
                evaluator.add_inplace(groups[a], term);
            }
        }
    }

    Ciphertext group1_rotated, group2_rotated;

    counted_rotate(evaluator, groups[1], rotation_sign * 4, galois_keys, group1_rotated, result.rotations);
    counted_rotate(evaluator, groups[2], rotation_sign * 8, galois_keys, group2_rotated, result.rotations);

    result.ciphertext = groups[0];
    evaluator.add_inplace(result.ciphertext, group1_rotated);
    evaluator.add_inplace(result.ciphertext, group2_rotated);
    evaluator.rescale_to_next_inplace(result.ciphertext);

    return result;
}

// ==================== 性能计时 ====================

template <typename Function>
double benchmark_ms(Function&& func, size_t repeats) {
    func();

    auto begin = chrono::steady_clock::now();
    for (size_t i = 0; i < repeats; i++) {
        func();
    }
    auto end = chrono::steady_clock::now();

    return chrono::duration<double, milli>(end - begin).count() / repeats;
}

// ==================== 主函数 ====================

int main() {
    cout << "========================================" << endl;
    cout << "  全同态加密卷积实验 (CKKS方案)" << endl;
    cout << "  作业5: 直接密文卷积" << endl;
    cout << "  作业6: BSGS旋转复用" << endl;
    cout << "========================================" << endl << endl;

    cout << "[1] 设置加密参数..." << endl;

    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 60 }));

    SEALContext context(parms);
    if (!context.parameters_set()) {
        cerr << "CKKS参数无效" << endl;
        return -1;
    }

    double scale = static_cast<double>(1ULL << 40);
    cout << "  参数设置完成" << endl << endl;

    cout << "[2] 生成密钥..." << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    cout << "  密钥生成完成" << endl << endl;

    int rotation_sign = 1;
    {
        vector<double> probe(encoder.slot_count(), 0.0);
        probe[0] = 1.0;
        probe[1] = 2.0;
        probe[2] = 3.0;
        Plaintext plain_probe;
        encoder.encode(probe, scale, plain_probe);
        Ciphertext enc_probe;
        encryptor.encrypt(plain_probe, enc_probe);

        Ciphertext rotated;
        evaluator.rotate_vector(enc_probe, 1, galois_keys, rotated);

        Plaintext plain_rotated;
        decryptor.decrypt(rotated, plain_rotated);
        vector<double> decoded;
        encoder.decode(plain_rotated, decoded);

        if (fabs(decoded[1] - 1.0) < 0.01) {
            rotation_sign = 1;
        }
        else {
            rotation_sign = -1;
        }
    }
    cout << "[3] 旋转方向检测完成" << endl << endl;

    cout << "[4] 准备测试数据..." << endl;

    vector<double> fixed_input = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };

    vector<double> fixed_kernel = {
        1, 2, 3,
        4, 5, 6,
        7, 8, 9
    };

    vector<double> expected = plaintext_correlation(fixed_input, fixed_kernel);

    cout << "  固定输入 (4x4):" << endl;
    print_matrix(fixed_input, kInputRows, kInputCols);
    cout << "  固定卷积核 (3x3):" << endl;
    print_matrix(fixed_kernel, kKernelRows, kKernelCols);
    cout << "  明文参考结果 (2x2):" << endl;
    print_matrix(expected, kOutputRows, kOutputCols);

    cout << "[5] 编码明文掩码..." << endl;

    size_t slot_count = encoder.slot_count();

    vector<Plaintext> direct_masks(kKernelSize);
    for (size_t i = 0; i < kKernelSize; i++) {
        vector<double> mask(slot_count, 0.0);
        for (size_t slot : kOutputSlots) {
            mask[slot] = fixed_kernel[i];
        }
        encoder.encode(mask, scale, direct_masks[i]);
    }

    vector<array<Plaintext, kKernelCols>> bsgs_masks(kKernelRows);
    for (size_t a = 0; a < kKernelRows; a++) {
        for (size_t b = 0; b < kKernelCols; b++) {
            vector<double> mask(slot_count, 0.0);
            for (size_t output_slot : kOutputSlots) {
                size_t pre_rotation_slot = output_slot + 4 * a;
                mask[pre_rotation_slot] = fixed_kernel[a * kKernelCols + b];
            }
            encoder.encode(mask, scale, bsgs_masks[a][b]);
        }
    }

    cout << "  掩码编码完成" << endl << endl;

    cout << "[6] 加密输入..." << endl;
    Ciphertext encrypted_input = encrypt_input(fixed_input, encoder, encryptor, scale);
    cout << "  输入已加密，槽位数: " << slot_count << endl << endl;

    cout << "[7] 作业5: 直接密文卷积..." << endl;

    ConvolutionResult direct_result = direct_convolution(
        encrypted_input,
        fixed_kernel,
        direct_masks,
        evaluator,
        galois_keys,
        relin_keys,
        rotation_sign);

    vector<double> direct_values = decrypt_output(direct_result.ciphertext, encoder, decryptor);

    double direct_error = max_abs_error(expected, direct_values);

    cout << "  旋转次数: " << direct_result.rotations << " (预期: 8)" << endl;
    cout << "  解密结果:" << endl;
    print_matrix(direct_values, kOutputRows, kOutputCols);
    cout << "  最大误差: " << scientific << direct_error << endl;
    cout << "  验证: " << (direct_error < kTolerance ? "PASS" : "FAIL") << endl << endl;

    cout << "[8] 作业6: BSGS密文卷积..." << endl;

    ConvolutionResult bsgs_result = bsgs_convolution(
        encrypted_input,
        bsgs_masks,
        evaluator,
        galois_keys,
        relin_keys,
        rotation_sign);

    vector<double> bsgs_values = decrypt_output(bsgs_result.ciphertext, encoder, decryptor);

    double bsgs_error = max_abs_error(expected, bsgs_values);
    double methods_error = max_abs_error(direct_values, bsgs_values);

    cout << "  旋转次数: " << bsgs_result.rotations << " (预期: 4)" << endl;
    cout << "  解密结果:" << endl;
    print_matrix(bsgs_values, kOutputRows, kOutputCols);
    cout << "  最大误差: " << scientific << bsgs_error << endl;
    cout << "  验证: " << (bsgs_error < kTolerance ? "PASS" : "FAIL") << endl << endl;

    cout << "[9] 固定样例综合验证" << endl;

    bool fixed_pass =
        (direct_result.rotations == 8) &&
        (bsgs_result.rotations == 4) &&
        (direct_error < kTolerance) &&
        (bsgs_error < kTolerance) &&
        (methods_error < kTolerance);

    cout << "  直接法旋转次数: " << direct_result.rotations << " (期望8) "
        << (direct_result.rotations == 8 ? "OK" : "FAIL") << endl;
    cout << "  BSGS法旋转次数: " << bsgs_result.rotations << " (期望4) "
        << (bsgs_result.rotations == 4 ? "OK" : "FAIL") << endl;
    cout << "  直接法误差: " << scientific << direct_error << " < 1e-4 "
        << (direct_error < kTolerance ? "OK" : "FAIL") << endl;
    cout << "  BSGS法误差: " << scientific << bsgs_error << " < 1e-4 "
        << (bsgs_error < kTolerance ? "OK" : "FAIL") << endl;
    cout << "  两方法间误差: " << scientific << methods_error << " < 1e-4 "
        << (methods_error < kTolerance ? "OK" : "FAIL") << endl;
    cout << "  固定样例: " << (fixed_pass ? "PASS" : "FAIL") << endl << endl;

    cout << "[10] 随机测试 (5组)" << endl;

    mt19937_64 rng(20260727ULL);
    uniform_real_distribution<double> dist(-1.0, 1.0);

    size_t passed = 0;
    double worst_error = 0.0;

    for (size_t test = 0; test < 5; test++) {
        vector<double> rand_input(kInputSize);
        vector<double> rand_kernel(kKernelSize);

        for (double& v : rand_input) v = dist(rng);
        for (double& v : rand_kernel) {
            v = dist(rng);
            if (fabs(v) < 0.05) {
                v = (v < 0.0) ? -0.05 : 0.05;
            }
        }

        Ciphertext rand_encrypted = encrypt_input(rand_input, encoder, encryptor, scale);

        vector<Plaintext> rand_direct_masks(kKernelSize);
        for (size_t i = 0; i < kKernelSize; i++) {
            vector<double> mask(slot_count, 0.0);
            for (size_t slot : kOutputSlots) {
                mask[slot] = rand_kernel[i];
            }
            encoder.encode(mask, scale, rand_direct_masks[i]);
        }

        vector<array<Plaintext, kKernelCols>> rand_bsgs_masks(kKernelRows);
        for (size_t a = 0; a < kKernelRows; a++) {
            for (size_t b = 0; b < kKernelCols; b++) {
                vector<double> mask(slot_count, 0.0);
                for (size_t output_slot : kOutputSlots) {
                    size_t pre_rotation_slot = output_slot + 4 * a;
                    mask[pre_rotation_slot] = rand_kernel[a * kKernelCols + b];
                }
                encoder.encode(mask, scale, rand_bsgs_masks[a][b]);
            }
        }

        vector<double> rand_expected = plaintext_correlation(rand_input, rand_kernel);

        ConvolutionResult rand_direct = direct_convolution(
            rand_encrypted, rand_kernel, rand_direct_masks,
            evaluator, galois_keys, relin_keys, rotation_sign);
        vector<double> rand_direct_vals = decrypt_output(rand_direct.ciphertext, encoder, decryptor);

        ConvolutionResult rand_bsgs = bsgs_convolution(
            rand_encrypted, rand_bsgs_masks,
            evaluator, galois_keys, relin_keys, rotation_sign);
        vector<double> rand_bsgs_vals = decrypt_output(rand_bsgs.ciphertext, encoder, decryptor);

        double err = max_abs_error(rand_expected, rand_bsgs_vals);
        worst_error = max(worst_error, err);

        bool pass = (rand_direct.rotations == 8) &&
            (rand_bsgs.rotations == 4) &&
            (err < kTolerance);

        if (pass) passed++;

        cout << "  测试" << (test + 1) << ": 误差=" << scientific << err
            << " " << (pass ? "PASS" : "FAIL") << endl;
    }

    cout << "  结果: " << passed << "/5 通过" << endl;
    cout << "  最坏误差: " << scientific << worst_error << endl << endl;

    cout << "[11] 性能测试" << endl;

    const size_t warmup = 1;
    const size_t repeats = 5;

    double direct_ms = benchmark_ms([&]() {
        ConvolutionResult _ = direct_convolution(
            encrypted_input, fixed_kernel, direct_masks,
            evaluator, galois_keys, relin_keys, rotation_sign);
        }, repeats);

    double bsgs_ms = benchmark_ms([&]() {
        ConvolutionResult _ = bsgs_convolution(
            encrypted_input, bsgs_masks,
            evaluator, galois_keys, relin_keys, rotation_sign);
        }, repeats);

    double speedup = direct_ms / bsgs_ms;

    cout << "  直接法平均耗时: " << fixed << setprecision(3) << direct_ms << " ms" << endl;
    cout << "  BSGS法平均耗时: " << fixed << setprecision(3) << bsgs_ms << " ms" << endl;
    cout << "  加速比: " << fixed << setprecision(3) << speedup << "x" << endl << endl;

    cout << "========================================" << endl;
    cout << "  最终状态" << endl;
    cout << "========================================" << endl;
    cout << "  固定样例: " << (fixed_pass ? "PASS" : "FAIL") << endl;
    cout << "  随机测试: " << passed << "/5 PASS" << endl;
    cout << "  直接法旋转: " << direct_result.rotations << " 次" << endl;
    cout << "  BSGS法旋转: " << bsgs_result.rotations << " 次" << endl;
    cout << "  加速比: " << fixed << setprecision(3) << speedup << "x" << endl;

    if (fixed_pass && passed == 5) {
        cout << endl << "全部通过" << endl;
    }
    else {
        cout << endl << "存在失败" << endl;
    }

    cout << "========================================" << endl;

    return 0;
}