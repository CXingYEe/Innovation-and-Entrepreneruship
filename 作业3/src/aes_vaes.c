/*
 * 复用基础实现中的AES密钥扩展、参考加密和输出函数。
 */
#define main aes_ref_embedded_selftest
#include "aes_ref.c"
#undef main

#include <immintrin.h>

/*
 * 将一个128位轮密钥复制到256位寄存器的两个128位通道。
 */
static __m256i duplicate_key_256(__m128i key)
{
    return _mm256_broadcastsi128_si256(key);
}

/*
 * 准备VAES加密和解密轮密钥。
 *
 * enc_keys中的每个256位轮密钥包含两个相同的128位轮密钥，
 * 以便同时处理两个AES分组。
 */
static void vaes_prepare_round_keys(
    const uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE],
    __m256i encrypt_keys[11],
    __m256i decrypt_keys[11])
{
    __m128i encrypt_keys_128[11];

    for (int round = 0; round <= 10; ++round) {
        encrypt_keys_128[round] =
            _mm_loadu_si128(
                (const __m128i *)
                (byte_round_keys + round * 16)
            );

        encrypt_keys[round] =
            duplicate_key_256(encrypt_keys_128[round]);
    }

    /*
     * 解密轮密钥的顺序与加密相反。
     */
    decrypt_keys[0] = encrypt_keys[10];

    for (int round = 1; round < 10; ++round) {
        __m128i transformed_key =
            _mm_aesimc_si128(
                encrypt_keys_128[10 - round]
            );

        decrypt_keys[round] =
            duplicate_key_256(transformed_key);
    }

    decrypt_keys[10] = encrypt_keys[0];
}

/*
 * 使用VAES同时加密两个16字节分组。
 *
 * input[0..15]  为第一个分组；
 * input[16..31] 为第二个分组。
 */
static void aes128_encrypt_vaes_2blocks(
    const uint8_t input[32],
    uint8_t output[32],
    const __m256i encrypt_keys[11])
{
    __m256i state =
        _mm256_loadu_si256((const __m256i *)input);

    state = _mm256_xor_si256(
        state,
        encrypt_keys[0]
    );

    for (int round = 1; round < 10; ++round) {
        state = _mm256_aesenc_epi128(
            state,
            encrypt_keys[round]
        );
    }

    state = _mm256_aesenclast_epi128(
        state,
        encrypt_keys[10]
    );

    _mm256_storeu_si256(
        (__m256i *)output,
        state
    );
}

/*
 * 使用VAES同时解密两个16字节分组。
 */
static void aes128_decrypt_vaes_2blocks(
    const uint8_t input[32],
    uint8_t output[32],
    const __m256i decrypt_keys[11])
{
    __m256i state =
        _mm256_loadu_si256((const __m256i *)input);

    state = _mm256_xor_si256(
        state,
        decrypt_keys[0]
    );

    for (int round = 1; round < 10; ++round) {
        state = _mm256_aesdec_epi128(
            state,
            decrypt_keys[round]
        );
    }

    state = _mm256_aesdeclast_epi128(
        state,
        decrypt_keys[10]
    );

    _mm256_storeu_si256(
        (__m256i *)output,
        state
    );
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

    /*
     * 第一个分组采用AES标准测试向量。
     * 第二个分组用于验证VAES双通道并行处理。
     */
    const uint8_t plaintext[32] = {
        /* Block 0 */
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff,

        /* Block 1 */
        0x6b,0xc1,0xbe,0xe2,
        0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,
        0x73,0x93,0x17,0x2a
    };

    const uint8_t expected_block0[16] = {
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    };

    uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE];

    __m256i encrypt_keys[11];
    __m256i decrypt_keys[11];

    uint8_t reference_ciphertext[32];
    uint8_t vaes_ciphertext[32];
    uint8_t recovered_plaintext[32];

#if defined(__GNUC__)
    int vaes_supported =
        __builtin_cpu_supports("vaes") != 0;

    int avx2_supported =
        __builtin_cpu_supports("avx2") != 0;
#else
    int vaes_supported = 1;
    int avx2_supported = 1;
#endif

    printf(
        "===== AES-128 VAES/AVX2 IMPLEMENTATION TEST =====\n"
    );

    printf(
        "VAES runtime support: %s\n",
        vaes_supported ? "YES" : "NO"
    );

    printf(
        "AVX2 runtime support: %s\n\n",
        avx2_supported ? "YES" : "NO"
    );

    if (!vaes_supported || !avx2_supported) {
        printf(
            "This CPU cannot run the VAES/AVX2 version.\n"
        );
        return 1;
    }

    aes128_key_expand(
        key,
        byte_round_keys
    );

    vaes_prepare_round_keys(
        byte_round_keys,
        encrypt_keys,
        decrypt_keys
    );

    /*
     * 分别使用基础版本加密两个分组，
     * 作为VAES结果的交叉验证基准。
     */
    aes128_encrypt_ref(
        plaintext,
        reference_ciphertext,
        byte_round_keys
    );

    aes128_encrypt_ref(
        plaintext + 16,
        reference_ciphertext + 16,
        byte_round_keys
    );

    aes128_encrypt_vaes_2blocks(
        plaintext,
        vaes_ciphertext,
        encrypt_keys
    );

    aes128_decrypt_vaes_2blocks(
        vaes_ciphertext,
        recovered_plaintext,
        decrypt_keys
    );

    int standard_kat_ok =
        memcmp(
            vaes_ciphertext,
            expected_block0,
            AES_BLOCK_SIZE
        ) == 0;

    int reference_match =
        memcmp(
            vaes_ciphertext,
            reference_ciphertext,
            sizeof(vaes_ciphertext)
        ) == 0;

    int decryption_ok =
        memcmp(
            recovered_plaintext,
            plaintext,
            sizeof(plaintext)
        ) == 0;

    print_hex("Key:", key, 16);

    printf("\n[Block 0: standard test vector]\n");

    print_hex(
        "Plaintext:",
        plaintext,
        16
    );

    print_hex(
        "Expected ciphertext:",
        expected_block0,
        16
    );

    print_hex(
        "VAES ciphertext:",
        vaes_ciphertext,
        16
    );

    printf("\n[Block 1: parallel test block]\n");

    print_hex(
        "Plaintext:",
        plaintext + 16,
        16
    );

    print_hex(
        "Reference ciphertext:",
        reference_ciphertext + 16,
        16
    );

    print_hex(
        "VAES ciphertext:",
        vaes_ciphertext + 16,
        16
    );

    printf("\n[Recovered plaintext]\n");

    print_hex(
        "Recovered block 0:",
        recovered_plaintext,
        16
    );

    print_hex(
        "Recovered block 1:",
        recovered_plaintext + 16,
        16
    );

    printf(
        "\nStandard vector KAT: %s\n",
        standard_kat_ok ? "PASS" : "FAIL"
    );

    printf(
        "Two-block reference match: %s\n",
        reference_match ? "PASS" : "FAIL"
    );

    printf(
        "Two-block decryption: %s\n",
        decryption_ok ? "PASS" : "FAIL"
    );

    printf(
        "Parallel blocks processed: 2\n"
    );

    printf(
        "Overall result: %s\n",
        standard_kat_ok &&
        reference_match &&
        decryption_ok
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    _mm256_zeroupper();

    return standard_kat_ok &&
           reference_match &&
           decryption_ok
               ? 0
               : 1;
}
#endif /* AES_NO_MAIN */
