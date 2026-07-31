#define AES_CTR_NO_MAIN
#include "aes_ctr.c"
#undef AES_CTR_NO_MAIN

#include <wmmintrin.h>
#include <tmmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void (*gf128_multiply_function)(
    const uint8_t x[16],
    const uint8_t y[16],
    uint8_t output[16]
);

/*
 * 常数时间比较。
 * 返回1表示两个数组完全相同。
 */
static int constant_time_equal(
    const uint8_t *a,
    const uint8_t *b,
    size_t length)
{
    uint8_t difference = 0;

    for (size_t i = 0; i < length; ++i) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }

    return difference == 0;
}

static void xor_block(
    uint8_t output[16],
    const uint8_t a[16],
    const uint8_t b[16])
{
    for (int i = 0; i < 16; ++i) {
        output[i] = a[i] ^ b[i];
    }
}

/*
 * GCM使用inc32：
 * 只增加计数器最低的32位。
 */
static void gcm_increment_counter(uint8_t counter[16])
{
    for (int i = 15; i >= 12; --i) {
        counter[i]++;

        if (counter[i] != 0) {
            break;
        }
    }
}

static void store_be64(uint8_t output[8], uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        output[i] = (uint8_t)value;
        value >>= 8;
    }
}

/*
 * 将128位大端数组整体右移1位。
 *
 * GCM逐位乘法中，若最低位为1，
 * 需要异或约简常数：
 *
 * R = E1000000000000000000000000000000
 */
static void shift_right_one(uint8_t value[16])
{
    uint8_t least_significant_bit =
        (uint8_t)(value[15] & 1u);

    for (int i = 15; i > 0; --i) {
        value[i] =
            (uint8_t)(
                (value[i] >> 1) |
                ((value[i - 1] & 1u) << 7)
            );
    }

    value[0] >>= 1;

    if (least_significant_bit != 0) {
        value[0] ^= 0xe1;
    }
}

/*
 * 基础GF(2^128)乘法。
 *
 * 采用NIST GCM定义中的逐位算法，
 * 共执行128轮条件异或与移位。
 */
static void gf128_multiply_reference(
    const uint8_t x[16],
    const uint8_t y[16],
    uint8_t output[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];

    memcpy(v, y, 16);

    for (int bit = 0; bit < 128; ++bit) {
        uint8_t selected_bit =
            (uint8_t)(
                x[bit / 8] &
                (1u << (7 - bit % 8))
            );

        if (selected_bit != 0) {
            for (int i = 0; i < 16; ++i) {
                z[i] ^= v[i];
            }
        }

        shift_right_one(v);
    }

    memcpy(output, z, 16);
}

/*
 * 使用PSHUFB完成每个字节内部的位逆序。
 *
 * GCM逐位表示中，每字节最高位对应较低次数项；
 * PCLMULQDQ中寄存器最低位对应最低次数项。
 * 因此在PCLMUL计算前后，需要进行位顺序转换。
 */
static __m128i reverse_bits_in_each_byte(__m128i value)
{
    const __m128i nibble_mask =
        _mm_set1_epi8(0x0f);

    const __m128i reverse_nibble =
        _mm_setr_epi8(
            0x0, 0x8, 0x4, 0xc,
            0x2, 0xa, 0x6, 0xe,
            0x1, 0x9, 0x5, 0xd,
            0x3, 0xb, 0x7, 0xf
        );

    __m128i low_nibble =
        _mm_and_si128(value, nibble_mask);

    __m128i high_nibble =
        _mm_and_si128(
            _mm_srli_epi16(value, 4),
            nibble_mask
        );

    __m128i reversed_low =
        _mm_shuffle_epi8(
            reverse_nibble,
            low_nibble
        );

    __m128i reversed_high =
        _mm_shuffle_epi8(
            reverse_nibble,
            high_nibble
        );

    return _mm_xor_si128(
        _mm_slli_epi16(reversed_low, 4),
        reversed_high
    );
}

/*
 * 在256位多项式表示中切换某一位。
 *
 * words[0]保存最低64位；
 * words[3]保存最高64位。
 */
static void toggle_polynomial_bit(
    uint64_t words[4],
    int bit_position)
{
    words[bit_position / 64] ^=
        UINT64_C(1) << (bit_position % 64);
}

/*
 * 将256位无进位乘积约简到128位。
 *
 * 使用不可约多项式：
 *
 * x^128 + x^7 + x^2 + x + 1
 *
 * 对每一个高于127位的项x^i，使用：
 *
 * x^i =
 * x^(i-128+7) +
 * x^(i-128+2) +
 * x^(i-128+1) +
 * x^(i-128)
 */
static void reduce_gcm_polynomial(
    uint64_t words[4])
{
    for (int bit = 255; bit >= 128; --bit) {
        uint64_t mask =
            UINT64_C(1) << (bit % 64);

        int word_index = bit / 64;

        if ((words[word_index] & mask) != 0) {
            /*
             * 清除当前高位项。
             */
            words[word_index] ^= mask;

            int shifted = bit - 128;

            toggle_polynomial_bit(
                words,
                shifted
            );

            toggle_polynomial_bit(
                words,
                shifted + 1
            );

            toggle_polynomial_bit(
                words,
                shifted + 2
            );

            toggle_polynomial_bit(
                words,
                shifted + 7
            );
        }
    }
}

/*
 * 使用PCLMULQDQ完成128x128位无进位乘法。
 *
 * 乘法使用4条64x64位PCLMUL指令；
 * 随后执行多项式约简。
 */
static void gf128_multiply_pclmul(
    const uint8_t x[16],
    const uint8_t y[16],
    uint8_t output[16])
{
    __m128i x_value =
        _mm_loadu_si128(
            (const __m128i *)x
        );

    __m128i y_value =
        _mm_loadu_si128(
            (const __m128i *)y
        );

    x_value =
        reverse_bits_in_each_byte(x_value);

    y_value =
        reverse_bits_in_each_byte(y_value);

    /*
     * 四个64x64位无进位乘法：
     *
     * x_low  * y_low
     * x_low  * y_high
     * x_high * y_low
     * x_high * y_high
     */
    __m128i product_low =
        _mm_clmulepi64_si128(
            x_value,
            y_value,
            0x00
        );

    __m128i product_high =
        _mm_clmulepi64_si128(
            x_value,
            y_value,
            0x11
        );

    __m128i product_cross_1 =
        _mm_clmulepi64_si128(
            x_value,
            y_value,
            0x01
        );

    __m128i product_cross_2 =
        _mm_clmulepi64_si128(
            x_value,
            y_value,
            0x10
        );

    __m128i product_cross =
        _mm_xor_si128(
            product_cross_1,
            product_cross_2
        );

    __m128i low_128 =
        _mm_xor_si128(
            product_low,
            _mm_slli_si128(product_cross, 8)
        );

    __m128i high_128 =
        _mm_xor_si128(
            product_high,
            _mm_srli_si128(product_cross, 8)
        );

    uint64_t words[4];

    _mm_storeu_si128(
        (__m128i *)&words[0],
        low_128
    );

    _mm_storeu_si128(
        (__m128i *)&words[2],
        high_128
    );

    reduce_gcm_polynomial(words);

    __m128i reduced =
        _mm_set_epi64x(
            (long long)words[1],
            (long long)words[0]
        );

    reduced =
        reverse_bits_in_each_byte(reduced);

    _mm_storeu_si128(
        (__m128i *)output,
        reduced
    );
}

/*
 * 对任意长度的数据执行GHASH分组处理。
 * 最后一个不足16字节的分组使用0填充。
 */
static void ghash_update(
    uint8_t state[16],
    const uint8_t hash_key[16],
    const uint8_t *data,
    size_t length,
    gf128_multiply_function multiply)
{
    while (length >= 16) {
        uint8_t temporary[16];

        xor_block(
            temporary,
            state,
            data
        );

        multiply(
            temporary,
            hash_key,
            state
        );

        data += 16;
        length -= 16;
    }

    if (length > 0) {
        uint8_t padded_block[16] = {0};
        uint8_t temporary[16];

        memcpy(
            padded_block,
            data,
            length
        );

        xor_block(
            temporary,
            state,
            padded_block
        );

        multiply(
            temporary,
            hash_key,
            state
        );
    }
}

/*
 * 计算完整GHASH：
 *
 * GHASH(H, A, C) =
 * A || pad || C || pad ||
 * len(A)_64 || len(C)_64
 */
static void compute_ghash(
    const uint8_t hash_key[16],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t output[16],
    gf128_multiply_function multiply)
{
    uint8_t state[16] = {0};
    uint8_t length_block[16] = {0};

    if (aad_length > 0) {
        ghash_update(
            state,
            hash_key,
            aad,
            aad_length,
            multiply
        );
    }

    if (ciphertext_length > 0) {
        ghash_update(
            state,
            hash_key,
            ciphertext,
            ciphertext_length,
            multiply
        );
    }

    store_be64(
        length_block,
        (uint64_t)aad_length * 8u
    );

    store_be64(
        length_block + 8,
        (uint64_t)ciphertext_length * 8u
    );

    ghash_update(
        state,
        hash_key,
        length_block,
        sizeof(length_block),
        multiply
    );

    memcpy(output, state, 16);
}

/*
 * AES-NI加密一个分组。
 */
static void aesni_encrypt_block(
    const uint8_t input[16],
    uint8_t output[16],
    const __m128i round_keys[11])
{
    __m128i state =
        _mm_loadu_si128(
            (const __m128i *)input
        );

    state =
        encrypt_state_aesni(
            state,
            round_keys
        );

    _mm_storeu_si128(
        (__m128i *)output,
        state
    );
}

/*
 * GCM中的CTR加解密。
 *
 * 对96位IV，J0 = IV || 00000001。
 * 第一个数据分组使用inc32(J0)。
 */
static void gcm_ctr_crypt(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t j0[16],
    const __m128i round_keys[11])
{
    uint8_t counter[16];
    uint8_t key_stream[16];

    memcpy(counter, j0, 16);

    while (length > 0) {
        gcm_increment_counter(counter);

        aesni_encrypt_block(
            counter,
            key_stream,
            round_keys
        );

        size_t current_length =
            length < 16 ? length : 16;

        for (size_t i = 0;
             i < current_length;
             ++i) {

            output[i] =
                input[i] ^ key_stream[i];
        }

        input += current_length;
        output += current_length;
        length -= current_length;
    }
}

/*
 * AES-GCM加密。
 *
 * 本实验固定使用96位IV，这是GCM最常用的IV长度。
 */
static void aes128_gcm_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_length,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t iv[12],
    uint8_t *ciphertext,
    uint8_t tag[16],
    const __m128i round_keys[11],
    gf128_multiply_function multiply)
{
    uint8_t zero_block[16] = {0};
    uint8_t hash_key[16];
    uint8_t j0[16] = {0};
    uint8_t authentication_state[16];
    uint8_t encrypted_j0[16];

    /*
     * H = AES_K(0^128)
     */
    aesni_encrypt_block(
        zero_block,
        hash_key,
        round_keys
    );

    /*
     * 96位IV时：
     *
     * J0 = IV || 0^31 || 1
     */
    memcpy(j0, iv, 12);
    j0[15] = 1;

    gcm_ctr_crypt(
        plaintext,
        ciphertext,
        plaintext_length,
        j0,
        round_keys
    );

    compute_ghash(
        hash_key,
        aad,
        aad_length,
        ciphertext,
        plaintext_length,
        authentication_state,
        multiply
    );

    aesni_encrypt_block(
        j0,
        encrypted_j0,
        round_keys
    );

    xor_block(
        tag,
        authentication_state,
        encrypted_j0
    );
}

/*
 * AES-GCM解密与标签验证。
 *
 * 必须先验证标签，再把明文交给调用者。
 */
static int aes128_gcm_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t iv[12],
    const uint8_t supplied_tag[16],
    uint8_t *plaintext,
    const __m128i round_keys[11],
    gf128_multiply_function multiply)
{
    uint8_t zero_block[16] = {0};
    uint8_t hash_key[16];
    uint8_t j0[16] = {0};
    uint8_t authentication_state[16];
    uint8_t encrypted_j0[16];
    uint8_t expected_tag[16];

    aesni_encrypt_block(
        zero_block,
        hash_key,
        round_keys
    );

    memcpy(j0, iv, 12);
    j0[15] = 1;

    compute_ghash(
        hash_key,
        aad,
        aad_length,
        ciphertext,
        ciphertext_length,
        authentication_state,
        multiply
    );

    aesni_encrypt_block(
        j0,
        encrypted_j0,
        round_keys
    );

    xor_block(
        expected_tag,
        authentication_state,
        encrypted_j0
    );

    if (!constant_time_equal(
            expected_tag,
            supplied_tag,
            16
        )) {

        memset(
            plaintext,
            0,
            ciphertext_length
        );

        return 0;
    }

    gcm_ctr_crypt(
        ciphertext,
        plaintext,
        ciphertext_length,
        j0,
        round_keys
    );

    return 1;
}

/*
 * 使用确定性输入比较基础有限域乘法和PCLMUL版本。
 */
static int test_pclmul_against_reference(void)
{
    for (int test = 0; test < 64; ++test) {
        uint8_t x[16];
        uint8_t y[16];
        uint8_t reference_result[16];
        uint8_t pclmul_result[16];

        for (int i = 0; i < 16; ++i) {
            x[i] = (uint8_t)(
                test * 17 + i * 29 + 3
            );

            y[i] = (uint8_t)(
                test * 31 + i * 7 + 11
            );
        }

        gf128_multiply_reference(
            x,
            y,
            reference_result
        );

        gf128_multiply_pclmul(
            x,
            y,
            pclmul_result
        );

        if (memcmp(
                reference_result,
                pclmul_result,
                16
            ) != 0) {

            return 0;
        }
    }

    return 1;
}

#ifndef AES_GCM_NO_MAIN
int main(void)
{
    /*
     * NIST AES-GCM已知答案测试：
     *
     * Key       = 00000000000000000000000000000000
     * IV        = 000000000000000000000000
     * Plaintext = 00000000000000000000000000000000
     *
     * Ciphertext:
     * 0388DACE60B6A392F328C2B971B2FE78
     *
     * Tag:
     * AB6E47D42CEC13BDF53A67B21257BDDF
     */
    const uint8_t key[16] = {0};
    const uint8_t iv[12] = {0};
    const uint8_t plaintext[16] = {0};

    const uint8_t expected_ciphertext[16] = {
        0x03,0x88,0xda,0xce,
        0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,
        0x71,0xb2,0xfe,0x78
    };

    const uint8_t expected_tag[16] = {
        0xab,0x6e,0x47,0xd4,
        0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,
        0x12,0x57,0xbd,0xdf
    };

    uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE];
    __m128i round_keys_128[11];
    __m256i unused_round_keys_256[11];

    uint8_t reference_ciphertext[16];
    uint8_t reference_tag[16];

    uint8_t pclmul_ciphertext[16];
    uint8_t pclmul_tag[16];

    uint8_t recovered_plaintext[16];
    uint8_t tampered_output[16];

    uint8_t tampered_tag[16];

#if defined(__GNUC__)
    int aes_supported =
        __builtin_cpu_supports("aes") != 0;

    int pclmul_supported =
        __builtin_cpu_supports("pclmul") != 0;

    int ssse3_supported =
        __builtin_cpu_supports("ssse3") != 0;
#else
    int aes_supported = 1;
    int pclmul_supported = 1;
    int ssse3_supported = 1;
#endif

    printf(
        "===== AES-128 GCM MODE TEST =====\n"
    );

    printf(
        "AES-NI runtime support : %s\n",
        aes_supported ? "YES" : "NO"
    );

    printf(
        "PCLMUL runtime support : %s\n",
        pclmul_supported ? "YES" : "NO"
    );

    printf(
        "SSSE3 runtime support  : %s\n\n",
        ssse3_supported ? "YES" : "NO"
    );

    if (!aes_supported ||
        !pclmul_supported ||
        !ssse3_supported) {

        printf(
            "Required instruction set is unavailable.\n"
        );

        return 1;
    }

    aes128_key_expand(
        key,
        byte_round_keys
    );

    prepare_encrypt_keys(
        byte_round_keys,
        round_keys_128,
        unused_round_keys_256
    );

    int multiplication_test_ok =
        test_pclmul_against_reference();

    aes128_gcm_encrypt(
        plaintext,
        sizeof(plaintext),
        NULL,
        0,
        iv,
        reference_ciphertext,
        reference_tag,
        round_keys_128,
        gf128_multiply_reference
    );

    aes128_gcm_encrypt(
        plaintext,
        sizeof(plaintext),
        NULL,
        0,
        iv,
        pclmul_ciphertext,
        pclmul_tag,
        round_keys_128,
        gf128_multiply_pclmul
    );

    int reference_ciphertext_ok =
        memcmp(
            reference_ciphertext,
            expected_ciphertext,
            16
        ) == 0;

    int reference_tag_ok =
        memcmp(
            reference_tag,
            expected_tag,
            16
        ) == 0;

    int pclmul_ciphertext_ok =
        memcmp(
            pclmul_ciphertext,
            expected_ciphertext,
            16
        ) == 0;

    int pclmul_tag_ok =
        memcmp(
            pclmul_tag,
            expected_tag,
            16
        ) == 0;

    int decryption_ok =
        aes128_gcm_decrypt(
            pclmul_ciphertext,
            sizeof(pclmul_ciphertext),
            NULL,
            0,
            iv,
            pclmul_tag,
            recovered_plaintext,
            round_keys_128,
            gf128_multiply_pclmul
        ) &&
        memcmp(
            recovered_plaintext,
            plaintext,
            16
        ) == 0;

    memcpy(
        tampered_tag,
        pclmul_tag,
        16
    );

    tampered_tag[15] ^= 0x01;

    int tampered_tag_rejected =
        !aes128_gcm_decrypt(
            pclmul_ciphertext,
            sizeof(pclmul_ciphertext),
            NULL,
            0,
            iv,
            tampered_tag,
            tampered_output,
            round_keys_128,
            gf128_multiply_pclmul
        );

    print_hex("Key:", key, 16);
    print_hex("IV:", iv, 12);
    print_hex("Plaintext:", plaintext, 16);

    print_hex(
        "Expected ciphertext:",
        expected_ciphertext,
        16
    );

    print_hex(
        "Reference ciphertext:",
        reference_ciphertext,
        16
    );

    print_hex(
        "PCLMUL ciphertext:",
        pclmul_ciphertext,
        16
    );

    print_hex(
        "Expected tag:",
        expected_tag,
        16
    );

    print_hex(
        "Reference tag:",
        reference_tag,
        16
    );

    print_hex(
        "PCLMUL tag:",
        pclmul_tag,
        16
    );

    printf(
        "\nGF multiply cross-check : %s\n",
        multiplication_test_ok ? "PASS" : "FAIL"
    );

    printf(
        "Reference ciphertext KAT: %s\n",
        reference_ciphertext_ok ? "PASS" : "FAIL"
    );

    printf(
        "Reference tag KAT       : %s\n",
        reference_tag_ok ? "PASS" : "FAIL"
    );

    printf(
        "PCLMUL ciphertext KAT   : %s\n",
        pclmul_ciphertext_ok ? "PASS" : "FAIL"
    );

    printf(
        "PCLMUL tag KAT          : %s\n",
        pclmul_tag_ok ? "PASS" : "FAIL"
    );

    printf(
        "Authenticated decryption: %s\n",
        decryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Tampered tag rejected   : %s\n",
        tampered_tag_rejected ? "PASS" : "FAIL"
    );

    int all_tests_passed =
        multiplication_test_ok &&
        reference_ciphertext_ok &&
        reference_tag_ok &&
        pclmul_ciphertext_ok &&
        pclmul_tag_ok &&
        decryption_ok &&
        tampered_tag_rejected;

    printf(
        "Overall result          : %s\n",
        all_tests_passed
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    _mm256_zeroupper();

    return all_tests_passed ? 0 : 1;
}
#endif
