/*
 * 复用基础实现中的密钥扩展、参考实现和输出函数。
 * 将原文件的 main 重命名，避免冲突。
 */
#define main aes_ref_embedded_selftest
#include "aes_ref.c"
#undef main

#include <wmmintrin.h>

/*
 * 将基础版本生成的 176 字节轮密钥转换为
 * AES-NI 使用的 11 个 128 位轮密钥。
 *
 * 解密轮密钥排列：
 *
 * dec[0]  = enc[10]
 * dec[1]  = AESIMC(enc[9])
 * ...
 * dec[9]  = AESIMC(enc[1])
 * dec[10] = enc[0]
 */
static void aesni_prepare_round_keys(
    const uint8_t round_keys[AES128_ROUND_KEYS_SIZE],
    __m128i encrypt_keys[11],
    __m128i decrypt_keys[11])
{
    for (int round = 0; round <= 10; ++round) {
        encrypt_keys[round] = _mm_loadu_si128(
            (const __m128i *)(round_keys + 16 * round)
        );
    }

    decrypt_keys[0] = encrypt_keys[10];

    for (int round = 1; round < 10; ++round) {
        decrypt_keys[round] =
            _mm_aesimc_si128(encrypt_keys[10 - round]);
    }

    decrypt_keys[10] = encrypt_keys[0];
}

/*
 * AES-NI 加密一个 16 字节分组。
 */
static void aes128_encrypt_aesni(
    const uint8_t input[16],
    uint8_t output[16],
    const __m128i encrypt_keys[11])
{
    __m128i state =
        _mm_loadu_si128((const __m128i *)input);

    state = _mm_xor_si128(state, encrypt_keys[0]);

    for (int round = 1; round < 10; ++round) {
        state = _mm_aesenc_si128(
            state,
            encrypt_keys[round]
        );
    }

    state = _mm_aesenclast_si128(
        state,
        encrypt_keys[10]
    );

    _mm_storeu_si128((__m128i *)output, state);
}

/*
 * AES-NI 解密一个 16 字节分组。
 */
static void aes128_decrypt_aesni(
    const uint8_t input[16],
    uint8_t output[16],
    const __m128i decrypt_keys[11])
{
    __m128i state =
        _mm_loadu_si128((const __m128i *)input);

    state = _mm_xor_si128(state, decrypt_keys[0]);

    for (int round = 1; round < 10; ++round) {
        state = _mm_aesdec_si128(
            state,
            decrypt_keys[round]
        );
    }

    state = _mm_aesdeclast_si128(
        state,
        decrypt_keys[10]
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

    uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE];

    __m128i encrypt_keys[11];
    __m128i decrypt_keys[11];

    uint8_t reference_ciphertext[16];
    uint8_t aesni_ciphertext[16];
    uint8_t recovered_plaintext[16];

#if defined(__GNUC__)
    int aesni_supported =
        __builtin_cpu_supports("aes") != 0;
#else
    int aesni_supported = 1;
#endif

    printf(
        "===== AES-128 AES-NI IMPLEMENTATION TEST =====\n"
    );

    printf(
        "AES-NI runtime support: %s\n\n",
        aesni_supported ? "YES" : "NO"
    );

    if (!aesni_supported) {
        printf("This CPU cannot run the AES-NI version.\n");
        return 1;
    }

    /*
     * 使用已经通过测试的基础密钥扩展。
     */
    aes128_key_expand(key, byte_round_keys);

    aesni_prepare_round_keys(
        byte_round_keys,
        encrypt_keys,
        decrypt_keys
    );

    /*
     * 计算基础版本结果，用于交叉比较。
     */
    aes128_encrypt_ref(
        plaintext,
        reference_ciphertext,
        byte_round_keys
    );

    aes128_encrypt_aesni(
        plaintext,
        aesni_ciphertext,
        encrypt_keys
    );

    aes128_decrypt_aesni(
        aesni_ciphertext,
        recovered_plaintext,
        decrypt_keys
    );

    int encryption_ok =
        memcmp(
            aesni_ciphertext,
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
            aesni_ciphertext,
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
        "AES-NI ciphertext:",
        aesni_ciphertext,
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
