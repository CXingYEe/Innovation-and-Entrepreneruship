/*
 * 复用基础实现中的S盒、逆S盒、密钥扩展和参考函数。
 * 将原文件中的main临时重命名，避免与本文件的main冲突。
 */
#define main aes_ref_embedded_selftest
#include "aes_ref.c"
#undef main

#include <tmmintrin.h>

/*
 * 对16个字节并行执行GF(2^8)中的乘2操作。
 *
 * doubled完成左移一位；
 * high_mask判断每个字节的最高位是否为1；
 * 若最高位为1，再异或AES约简多项式常数0x1B。
 */
static __m128i xtime_vec(__m128i x)
{
    const __m128i zero = _mm_setzero_si128();
    const __m128i reduction = _mm_set1_epi8(0x1b);

    __m128i doubled = _mm_add_epi8(x, x);

    /*
     * 字节最高位为1时，按有符号数看该字节小于0。
     */
    __m128i high_mask = _mm_cmpgt_epi8(zero, x);

    return _mm_xor_si128(
        doubled,
        _mm_and_si128(high_mask, reduction)
    );
}

/*
 * S盒替换仍使用基础版本的SBOX。
 * Shuffle版本主要优化行移位和列混合。
 */
static __m128i sub_bytes_vec(__m128i state)
{
    uint8_t bytes[16];

    _mm_storeu_si128((__m128i *)bytes, state);

    for (int i = 0; i < 16; ++i) {
        bytes[i] = SBOX[bytes[i]];
    }

    return _mm_loadu_si128((const __m128i *)bytes);
}

static __m128i inv_sub_bytes_vec(__m128i state)
{
    uint8_t bytes[16];

    _mm_storeu_si128((__m128i *)bytes, state);

    for (int i = 0; i < 16; ++i) {
        bytes[i] = INV_SBOX[bytes[i]];
    }

    return _mm_loadu_si128((const __m128i *)bytes);
}

/*
 * 使用一条PSHUFB完成ShiftRows。
 *
 * 输出位置i从掩码指定的输入位置读取字节。
 */
static __m128i shift_rows_vec(__m128i state)
{
    const __m128i mask = _mm_setr_epi8(
         0,  5, 10, 15,
         4,  9, 14,  3,
         8, 13,  2,  7,
        12,  1,  6, 11
    );

    return _mm_shuffle_epi8(state, mask);
}

/*
 * 使用一条PSHUFB完成InvShiftRows。
 */
static __m128i inv_shift_rows_vec(__m128i state)
{
    const __m128i mask = _mm_setr_epi8(
         0, 13, 10,  7,
         4,  1, 14, 11,
         8,  5,  2, 15,
        12,  9,  6,  3
    );

    return _mm_shuffle_epi8(state, mask);
}

/*
 * 同时对4个AES列执行MixColumns。
 *
 * 对每个列[a0,a1,a2,a3]构造：
 * rot1 = [a1,a2,a3,a0]
 * rot2 = [a2,a3,a0,a1]
 * rot3 = [a3,a0,a1,a2]
 *
 * 结果为：
 * 2*a + 2*rot1 + rot1 + rot2 + rot3
 */
static __m128i mix_columns_vec(__m128i state)
{
    const __m128i rotate1_mask = _mm_setr_epi8(
         1,  2,  3,  0,
         5,  6,  7,  4,
         9, 10, 11,  8,
        13, 14, 15, 12
    );

    const __m128i rotate2_mask = _mm_setr_epi8(
         2,  3,  0,  1,
         6,  7,  4,  5,
        10, 11,  8,  9,
        14, 15, 12, 13
    );

    const __m128i rotate3_mask = _mm_setr_epi8(
         3,  0,  1,  2,
         7,  4,  5,  6,
        11,  8,  9, 10,
        15, 12, 13, 14
    );

    __m128i rot1 =
        _mm_shuffle_epi8(state, rotate1_mask);

    __m128i rot2 =
        _mm_shuffle_epi8(state, rotate2_mask);

    __m128i rot3 =
        _mm_shuffle_epi8(state, rotate3_mask);

    __m128i result =
        _mm_xor_si128(
            xtime_vec(state),
            xtime_vec(rot1)
        );

    result = _mm_xor_si128(result, rot1);
    result = _mm_xor_si128(result, rot2);
    result = _mm_xor_si128(result, rot3);

    return result;
}

/*
 * InvMixColumns可转换为：
 *
 * u = 4 * (a0 XOR a2)
 * v = 4 * (a1 XOR a3)
 *
 * a0 ^= u; a2 ^= u;
 * a1 ^= v; a3 ^= v;
 *
 * 再执行一次普通MixColumns。
 */
static __m128i inv_mix_columns_vec(__m128i state)
{
    const __m128i rotate2_mask = _mm_setr_epi8(
         2,  3,  0,  1,
         6,  7,  4,  5,
        10, 11,  8,  9,
        14, 15, 12, 13
    );

    __m128i rotated =
        _mm_shuffle_epi8(state, rotate2_mask);

    __m128i correction =
        _mm_xor_si128(state, rotated);

    correction = xtime_vec(correction);
    correction = xtime_vec(correction);

    state = _mm_xor_si128(state, correction);

    return mix_columns_vec(state);
}

static __m128i load_round_key(
    const uint8_t round_keys[AES128_ROUND_KEYS_SIZE],
    int round)
{
    return _mm_loadu_si128(
        (const __m128i *)(round_keys + round * 16)
    );
}

static void aes128_encrypt_shuffle(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t round_keys[AES128_ROUND_KEYS_SIZE])
{
    __m128i state =
        _mm_loadu_si128((const __m128i *)input);

    state = _mm_xor_si128(
        state,
        load_round_key(round_keys, 0)
    );

    for (int round = 1; round < 10; ++round) {
        state = sub_bytes_vec(state);
        state = shift_rows_vec(state);
        state = mix_columns_vec(state);

        state = _mm_xor_si128(
            state,
            load_round_key(round_keys, round)
        );
    }

    state = sub_bytes_vec(state);
    state = shift_rows_vec(state);

    state = _mm_xor_si128(
        state,
        load_round_key(round_keys, 10)
    );

    _mm_storeu_si128((__m128i *)output, state);
}

static void aes128_decrypt_shuffle(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t round_keys[AES128_ROUND_KEYS_SIZE])
{
    __m128i state =
        _mm_loadu_si128((const __m128i *)input);

    state = _mm_xor_si128(
        state,
        load_round_key(round_keys, 10)
    );

    for (int round = 9; round > 0; --round) {
        state = inv_shift_rows_vec(state);
        state = inv_sub_bytes_vec(state);

        state = _mm_xor_si128(
            state,
            load_round_key(round_keys, round)
        );

        state = inv_mix_columns_vec(state);
    }

    state = inv_shift_rows_vec(state);
    state = inv_sub_bytes_vec(state);

    state = _mm_xor_si128(
        state,
        load_round_key(round_keys, 0)
    );

    _mm_storeu_si128((__m128i *)output, state);
}

#ifndef AES_NO_MAIN
int main(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    };

    const uint8_t expected_ciphertext[16] = {
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    };

    uint8_t round_keys[AES128_ROUND_KEYS_SIZE];

    uint8_t shuffle_ciphertext[16];
    uint8_t reference_ciphertext[16];
    uint8_t recovered_plaintext[16];

#if defined(__GNUC__)
    int ssse3_supported =
        __builtin_cpu_supports("ssse3") != 0;
#else
    int ssse3_supported = 1;
#endif

    printf(
        "===== AES-128 SHUFFLE/SSSE3 IMPLEMENTATION TEST =====\n"
    );

    printf(
        "SSSE3 runtime support: %s\n\n",
        ssse3_supported ? "YES" : "NO"
    );

    if (!ssse3_supported) {
        printf("This CPU cannot run the shuffle version.\n");
        return 1;
    }

    aes128_key_expand(key, round_keys);

    aes128_encrypt_ref(
        plaintext,
        reference_ciphertext,
        round_keys
    );

    aes128_encrypt_shuffle(
        plaintext,
        shuffle_ciphertext,
        round_keys
    );

    aes128_decrypt_shuffle(
        shuffle_ciphertext,
        recovered_plaintext,
        round_keys
    );

    int encryption_ok =
        memcmp(
            shuffle_ciphertext,
            expected_ciphertext,
            AES_BLOCK_SIZE
        ) == 0;

    int decryption_ok =
        memcmp(
            recovered_plaintext,
            plaintext,
            AES_BLOCK_SIZE
        ) == 0;

    int reference_match =
        memcmp(
            shuffle_ciphertext,
            reference_ciphertext,
            AES_BLOCK_SIZE
        ) == 0;

    print_hex("Key:", key, 16);
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
        "Shuffle ciphertext:",
        shuffle_ciphertext,
        16
    );

    print_hex(
        "Recovered plaintext:",
        recovered_plaintext,
        16
    );

    printf(
        "\nEncryption KAT: %s\n",
        encryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Decryption KAT: %s\n",
        decryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Matches reference: %s\n",
        reference_match ? "PASS" : "FAIL"
    );

    printf(
        "Overall result: %s\n",
        encryption_ok &&
        decryption_ok &&
        reference_match
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    return encryption_ok &&
           decryption_ok &&
           reference_match
               ? 0
               : 1;
}
#endif /* AES_NO_MAIN */
