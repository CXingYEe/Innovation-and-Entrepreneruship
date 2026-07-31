#define AES_NO_MAIN
#include "aes_aesni.c"
#undef AES_NO_MAIN

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * XTS中tweak乘以alpha。
 *
 * XTS采用小端多项式表示：
 * 如果最高位产生进位，则最低字节异或0x87。
 */
static void xts_multiply_alpha(uint8_t tweak[16])
{
    unsigned int carry = 0;

    for (int i = 0; i < 16; ++i) {
        unsigned int value = tweak[i];
        unsigned int next_carry = value >> 7;

        tweak[i] = (uint8_t)(
            (value << 1) | carry
        );

        carry = next_carry;
    }

    if (carry != 0) {
        tweak[0] ^= 0x87;
    }
}

static void xor_with_tweak(
    uint8_t output[16],
    const uint8_t input[16],
    const uint8_t tweak[16])
{
    for (int i = 0; i < 16; ++i) {
        output[i] = input[i] ^ tweak[i];
    }
}

/* 使用基础软件AES完成一个XTS分组加密 */
static void xts_encrypt_block_reference(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t tweak[16],
    const uint8_t data_round_keys[
        AES128_ROUND_KEYS_SIZE
    ])
{
    uint8_t temporary[16];

    xor_with_tweak(
        temporary,
        input,
        tweak
    );

    aes128_encrypt_ref(
        temporary,
        temporary,
        data_round_keys
    );

    xor_with_tweak(
        output,
        temporary,
        tweak
    );
}

/* 使用基础软件AES完成一个XTS分组解密 */
static void xts_decrypt_block_reference(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t tweak[16],
    const uint8_t data_round_keys[
        AES128_ROUND_KEYS_SIZE
    ])
{
    uint8_t temporary[16];

    xor_with_tweak(
        temporary,
        input,
        tweak
    );

    aes128_decrypt_ref(
        temporary,
        temporary,
        data_round_keys
    );

    xor_with_tweak(
        output,
        temporary,
        tweak
    );
}

/* 使用AES-NI完成一个XTS分组加密 */
static void xts_encrypt_block_aesni(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t tweak[16],
    const __m128i encrypt_keys[11])
{
    __m128i state =
        _mm_loadu_si128(
            (const __m128i *)input
        );

    __m128i tweak_value =
        _mm_loadu_si128(
            (const __m128i *)tweak
        );

    state = _mm_xor_si128(
        state,
        tweak_value
    );

    state = _mm_xor_si128(
        state,
        encrypt_keys[0]
    );

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

    state = _mm_xor_si128(
        state,
        tweak_value
    );

    _mm_storeu_si128(
        (__m128i *)output,
        state
    );
}

/* 使用AES-NI完成一个XTS分组解密 */
static void xts_decrypt_block_aesni(
    const uint8_t input[16],
    uint8_t output[16],
    const uint8_t tweak[16],
    const __m128i decrypt_keys[11])
{
    __m128i state =
        _mm_loadu_si128(
            (const __m128i *)input
        );

    __m128i tweak_value =
        _mm_loadu_si128(
            (const __m128i *)tweak
        );

    state = _mm_xor_si128(
        state,
        tweak_value
    );

    state = _mm_xor_si128(
        state,
        decrypt_keys[0]
    );

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

    state = _mm_xor_si128(
        state,
        tweak_value
    );

    _mm_storeu_si128(
        (__m128i *)output,
        state
    );
}

/*
 * AES-NI八分组流水线XTS加密。
 * 每个分组拥有不同的tweak。
 */
static void xts_encrypt_8blocks_aesni(
    const uint8_t input[128],
    uint8_t output[128],
    const uint8_t tweaks[128],
    const __m128i encrypt_keys[11])
{
    __m128i state[8];
    __m128i tweak_values[8];

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_loadu_si128(
            (const __m128i *)(input + i * 16)
        );

        tweak_values[i] = _mm_loadu_si128(
            (const __m128i *)(tweaks + i * 16)
        );

        state[i] = _mm_xor_si128(
            state[i],
            tweak_values[i]
        );

        state[i] = _mm_xor_si128(
            state[i],
            encrypt_keys[0]
        );
    }

    for (int round = 1; round < 10; ++round) {
        for (int i = 0; i < 8; ++i) {
            state[i] = _mm_aesenc_si128(
                state[i],
                encrypt_keys[round]
            );
        }
    }

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_aesenclast_si128(
            state[i],
            encrypt_keys[10]
        );

        state[i] = _mm_xor_si128(
            state[i],
            tweak_values[i]
        );

        _mm_storeu_si128(
            (__m128i *)(output + i * 16),
            state[i]
        );
    }
}

/* AES-NI八分组流水线XTS解密 */
static void xts_decrypt_8blocks_aesni(
    const uint8_t input[128],
    uint8_t output[128],
    const uint8_t tweaks[128],
    const __m128i decrypt_keys[11])
{
    __m128i state[8];
    __m128i tweak_values[8];

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_loadu_si128(
            (const __m128i *)(input + i * 16)
        );

        tweak_values[i] = _mm_loadu_si128(
            (const __m128i *)(tweaks + i * 16)
        );

        state[i] = _mm_xor_si128(
            state[i],
            tweak_values[i]
        );

        state[i] = _mm_xor_si128(
            state[i],
            decrypt_keys[0]
        );
    }

    for (int round = 1; round < 10; ++round) {
        for (int i = 0; i < 8; ++i) {
            state[i] = _mm_aesdec_si128(
                state[i],
                decrypt_keys[round]
            );
        }
    }

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_aesdeclast_si128(
            state[i],
            decrypt_keys[10]
        );

        state[i] = _mm_xor_si128(
            state[i],
            tweak_values[i]
        );

        _mm_storeu_si128(
            (__m128i *)(output + i * 16),
            state[i]
        );
    }
}

/*
 * 基础软件XTS加密。
 * 支持完整分组和最后一个非完整分组的密文窃取。
 */
static int aes128_xts_encrypt_reference(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t tweak_input[16],
    const uint8_t data_round_keys[
        AES128_ROUND_KEYS_SIZE
    ],
    const uint8_t tweak_round_keys[
        AES128_ROUND_KEYS_SIZE
    ])
{
    if (length < 16) {
        return 0;
    }

    uint8_t tweak[16];

    aes128_encrypt_ref(
        tweak_input,
        tweak,
        tweak_round_keys
    );

    size_t full_blocks = length / 16;
    size_t remaining = length % 16;

    size_t ordinary_blocks =
        remaining == 0
            ? full_blocks
            : full_blocks - 1;

    for (size_t block = 0;
         block < ordinary_blocks;
         ++block) {

        xts_encrypt_block_reference(
            input + block * 16,
            output + block * 16,
            tweak,
            data_round_keys
        );

        xts_multiply_alpha(tweak);
    }

    if (remaining == 0) {
        return 1;
    }

    uint8_t temporary_ciphertext[16];
    uint8_t stolen_plaintext[16];
    uint8_t next_tweak[16];

    size_t last_full_offset =
        (full_blocks - 1) * 16;

    size_t partial_offset =
        full_blocks * 16;

    xts_encrypt_block_reference(
        input + last_full_offset,
        temporary_ciphertext,
        tweak,
        data_round_keys
    );

    memcpy(
        output + partial_offset,
        temporary_ciphertext,
        remaining
    );

    memcpy(
        stolen_plaintext,
        input + partial_offset,
        remaining
    );

    memcpy(
        stolen_plaintext + remaining,
        temporary_ciphertext + remaining,
        16 - remaining
    );

    memcpy(next_tweak, tweak, 16);
    xts_multiply_alpha(next_tweak);

    xts_encrypt_block_reference(
        stolen_plaintext,
        output + last_full_offset,
        next_tweak,
        data_round_keys
    );

    return 1;
}

/* 基础软件XTS解密 */
static int aes128_xts_decrypt_reference(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t tweak_input[16],
    const uint8_t data_round_keys[
        AES128_ROUND_KEYS_SIZE
    ],
    const uint8_t tweak_round_keys[
        AES128_ROUND_KEYS_SIZE
    ])
{
    if (length < 16) {
        return 0;
    }

    uint8_t tweak[16];

    aes128_encrypt_ref(
        tweak_input,
        tweak,
        tweak_round_keys
    );

    size_t full_blocks = length / 16;
    size_t remaining = length % 16;

    size_t ordinary_blocks =
        remaining == 0
            ? full_blocks
            : full_blocks - 1;

    for (size_t block = 0;
         block < ordinary_blocks;
         ++block) {

        xts_decrypt_block_reference(
            input + block * 16,
            output + block * 16,
            tweak,
            data_round_keys
        );

        xts_multiply_alpha(tweak);
    }

    if (remaining == 0) {
        return 1;
    }

    uint8_t reconstructed_block[16];
    uint8_t partial_plaintext[16];
    uint8_t next_tweak[16];

    size_t last_full_offset =
        (full_blocks - 1) * 16;

    size_t partial_offset =
        full_blocks * 16;

    memcpy(next_tweak, tweak, 16);
    xts_multiply_alpha(next_tweak);

    xts_decrypt_block_reference(
        input + last_full_offset,
        partial_plaintext,
        next_tweak,
        data_round_keys
    );

    memcpy(
        output + partial_offset,
        partial_plaintext,
        remaining
    );

    memcpy(
        reconstructed_block,
        input + partial_offset,
        remaining
    );

    memcpy(
        reconstructed_block + remaining,
        partial_plaintext + remaining,
        16 - remaining
    );

    xts_decrypt_block_reference(
        reconstructed_block,
        output + last_full_offset,
        tweak,
        data_round_keys
    );

    return 1;
}

/*
 * AES-NI优化XTS加密。
 * 普通完整分组使用八分组流水线；
 * 密文窃取部分使用单分组处理。
 */
static int aes128_xts_encrypt_aesni8(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t tweak_input[16],
    const __m128i data_encrypt_keys[11],
    const __m128i tweak_encrypt_keys[11])
{
    if (length < 16) {
        return 0;
    }

    uint8_t tweak[16];

    aes128_encrypt_aesni(
        tweak_input,
        tweak,
        tweak_encrypt_keys
    );

    size_t full_blocks = length / 16;
    size_t remaining = length % 16;

    size_t ordinary_blocks =
        remaining == 0
            ? full_blocks
            : full_blocks - 1;

    size_t block = 0;
    size_t groups_of_eight = ordinary_blocks / 8;

    for (size_t group = 0;
         group < groups_of_eight;
         ++group) {
        uint8_t tweaks[128];

        for (int i = 0; i < 8; ++i) {
            memcpy(
                tweaks + i * 16,
                tweak,
                16
            );

            xts_multiply_alpha(tweak);
        }

        xts_encrypt_8blocks_aesni(
            input + block * 16,
            output + block * 16,
            tweaks,
            data_encrypt_keys
        );

        block += 8;
    }

    while (block < ordinary_blocks) {
        xts_encrypt_block_aesni(
            input + block * 16,
            output + block * 16,
            tweak,
            data_encrypt_keys
        );

        xts_multiply_alpha(tweak);
        ++block;
    }

    if (remaining == 0) {
        return 1;
    }

    uint8_t temporary_ciphertext[16];
    uint8_t stolen_plaintext[16];
    uint8_t next_tweak[16];

    size_t last_full_offset =
        (full_blocks - 1) * 16;

    size_t partial_offset =
        full_blocks * 16;

    xts_encrypt_block_aesni(
        input + last_full_offset,
        temporary_ciphertext,
        tweak,
        data_encrypt_keys
    );

    memcpy(
        output + partial_offset,
        temporary_ciphertext,
        remaining
    );

    memcpy(
        stolen_plaintext,
        input + partial_offset,
        remaining
    );

    memcpy(
        stolen_plaintext + remaining,
        temporary_ciphertext + remaining,
        16 - remaining
    );

    memcpy(next_tweak, tweak, 16);
    xts_multiply_alpha(next_tweak);

    xts_encrypt_block_aesni(
        stolen_plaintext,
        output + last_full_offset,
        next_tweak,
        data_encrypt_keys
    );

    return 1;
}

/* AES-NI优化XTS解密 */
static int aes128_xts_decrypt_aesni8(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t tweak_input[16],
    const __m128i data_decrypt_keys[11],
    const __m128i tweak_encrypt_keys[11])
{
    if (length < 16) {
        return 0;
    }

    uint8_t tweak[16];

    aes128_encrypt_aesni(
        tweak_input,
        tweak,
        tweak_encrypt_keys
    );

    size_t full_blocks = length / 16;
    size_t remaining = length % 16;

    size_t ordinary_blocks =
        remaining == 0
            ? full_blocks
            : full_blocks - 1;

    size_t block = 0;
    size_t groups_of_eight = ordinary_blocks / 8;

    for (size_t group = 0;
         group < groups_of_eight;
         ++group) {
        uint8_t tweaks[128];

        for (int i = 0; i < 8; ++i) {
            memcpy(
                tweaks + i * 16,
                tweak,
                16
            );

            xts_multiply_alpha(tweak);
        }

        xts_decrypt_8blocks_aesni(
            input + block * 16,
            output + block * 16,
            tweaks,
            data_decrypt_keys
        );

        block += 8;
    }

    while (block < ordinary_blocks) {
        xts_decrypt_block_aesni(
            input + block * 16,
            output + block * 16,
            tweak,
            data_decrypt_keys
        );

        xts_multiply_alpha(tweak);
        ++block;
    }

    if (remaining == 0) {
        return 1;
    }

    uint8_t reconstructed_block[16];
    uint8_t partial_plaintext[16];
    uint8_t next_tweak[16];

    size_t last_full_offset =
        (full_blocks - 1) * 16;

    size_t partial_offset =
        full_blocks * 16;

    memcpy(next_tweak, tweak, 16);
    xts_multiply_alpha(next_tweak);

    xts_decrypt_block_aesni(
        input + last_full_offset,
        partial_plaintext,
        next_tweak,
        data_decrypt_keys
    );

    memcpy(
        output + partial_offset,
        partial_plaintext,
        remaining
    );

    memcpy(
        reconstructed_block,
        input + partial_offset,
        remaining
    );

    memcpy(
        reconstructed_block + remaining,
        partial_plaintext + remaining,
        16 - remaining
    );

    xts_decrypt_block_aesni(
        reconstructed_block,
        output + last_full_offset,
        tweak,
        data_decrypt_keys
    );

    return 1;
}

/*
 * 使用OpenSSL EVP作为独立交叉验证实现。
 */
static int openssl_xts_crypt(
    int encrypt,
    const uint8_t combined_key[32],
    const uint8_t tweak_input[16],
    const uint8_t *input,
    size_t length,
    uint8_t *output)
{
    if (length > INT32_MAX) {
        return 0;
    }

    EVP_CIPHER_CTX *context =
        EVP_CIPHER_CTX_new();

    if (context == NULL) {
        return 0;
    }

    int output_length_1 = 0;
    int output_length_2 = 0;
    int success = 0;

    if (EVP_CipherInit_ex(
            context,
            EVP_aes_128_xts(),
            NULL,
            combined_key,
            tweak_input,
            encrypt
        ) != 1) {

        goto cleanup;
    }

    if (EVP_CIPHER_CTX_set_padding(
            context,
            0
        ) != 1) {

        goto cleanup;
    }

    if (EVP_CipherUpdate(
            context,
            output,
            &output_length_1,
            input,
            (int)length
        ) != 1) {

        goto cleanup;
    }

    if (EVP_CipherFinal_ex(
            context,
            output + output_length_1,
            &output_length_2
        ) != 1) {

        goto cleanup;
    }

    success =
        (size_t)(
            output_length_1 + output_length_2
        ) == length;

cleanup:
    EVP_CIPHER_CTX_free(context);
    return success;
}

#ifndef AES_XTS_NO_MAIN
int main(void)
{
    const uint8_t combined_key[32] = {
        /* 数据密钥K1 */
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,

        /* tweak密钥K2 */
        0x10,0x11,0x12,0x13,
        0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,
        0x1c,0x1d,0x1e,0x1f
    };

    const uint8_t tweak_input[16] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x01
    };

    uint8_t full_plaintext[64];
    uint8_t partial_plaintext[47];

    uint8_t openssl_full[64];
    uint8_t reference_full[64];
    uint8_t aesni_full[64];

    uint8_t openssl_partial[47];
    uint8_t reference_partial[47];
    uint8_t aesni_partial[47];

    uint8_t reference_full_recovered[64];
    uint8_t aesni_full_recovered[64];

    uint8_t reference_partial_recovered[47];
    uint8_t aesni_partial_recovered[47];

    uint8_t data_round_keys[
        AES128_ROUND_KEYS_SIZE
    ];

    uint8_t tweak_round_keys[
        AES128_ROUND_KEYS_SIZE
    ];

    __m128i data_encrypt_keys[11];
    __m128i data_decrypt_keys[11];

    __m128i tweak_encrypt_keys[11];
    __m128i unused_tweak_decrypt_keys[11];

    for (size_t i = 0;
         i < sizeof(full_plaintext);
         ++i) {

        full_plaintext[i] =
            (uint8_t)(i * 13u + 7u);
    }

    for (size_t i = 0;
         i < sizeof(partial_plaintext);
         ++i) {

        partial_plaintext[i] =
            (uint8_t)(i * 19u + 11u);
    }

#if defined(__GNUC__)
    int aes_supported =
        __builtin_cpu_supports("aes") != 0;
#else
    int aes_supported = 1;
#endif

    printf(
        "===== AES-128 XTS MODE TEST =====\n"
    );

    printf(
        "AES-NI runtime support : %s\n",
        aes_supported ? "YES" : "NO"
    );

    printf(
        "OpenSSL XTS oracle      : ENABLED\n"
    );

    printf(
        "Full-block length       : 64 bytes\n"
    );

    printf(
        "CTS test length         : 47 bytes\n\n"
    );

    if (!aes_supported) {
        return 1;
    }

    aes128_key_expand(
        combined_key,
        data_round_keys
    );

    aes128_key_expand(
        combined_key + 16,
        tweak_round_keys
    );

    aesni_prepare_round_keys(
        data_round_keys,
        data_encrypt_keys,
        data_decrypt_keys
    );

    aesni_prepare_round_keys(
        tweak_round_keys,
        tweak_encrypt_keys,
        unused_tweak_decrypt_keys
    );

    int openssl_full_ok =
        openssl_xts_crypt(
            1,
            combined_key,
            tweak_input,
            full_plaintext,
            sizeof(full_plaintext),
            openssl_full
        );

    int openssl_partial_ok =
        openssl_xts_crypt(
            1,
            combined_key,
            tweak_input,
            partial_plaintext,
            sizeof(partial_plaintext),
            openssl_partial
        );

    int reference_full_ok =
        aes128_xts_encrypt_reference(
            full_plaintext,
            reference_full,
            sizeof(full_plaintext),
            tweak_input,
            data_round_keys,
            tweak_round_keys
        );

    int reference_partial_ok =
        aes128_xts_encrypt_reference(
            partial_plaintext,
            reference_partial,
            sizeof(partial_plaintext),
            tweak_input,
            data_round_keys,
            tweak_round_keys
        );

    int aesni_full_ok =
        aes128_xts_encrypt_aesni8(
            full_plaintext,
            aesni_full,
            sizeof(full_plaintext),
            tweak_input,
            data_encrypt_keys,
            tweak_encrypt_keys
        );

    int aesni_partial_ok =
        aes128_xts_encrypt_aesni8(
            partial_plaintext,
            aesni_partial,
            sizeof(partial_plaintext),
            tweak_input,
            data_encrypt_keys,
            tweak_encrypt_keys
        );

    int full_reference_match =
        openssl_full_ok &&
        reference_full_ok &&
        memcmp(
            openssl_full,
            reference_full,
            sizeof(openssl_full)
        ) == 0;

    int full_aesni_match =
        openssl_full_ok &&
        aesni_full_ok &&
        memcmp(
            openssl_full,
            aesni_full,
            sizeof(openssl_full)
        ) == 0;

    int partial_reference_match =
        openssl_partial_ok &&
        reference_partial_ok &&
        memcmp(
            openssl_partial,
            reference_partial,
            sizeof(openssl_partial)
        ) == 0;

    int partial_aesni_match =
        openssl_partial_ok &&
        aesni_partial_ok &&
        memcmp(
            openssl_partial,
            aesni_partial,
            sizeof(openssl_partial)
        ) == 0;

    int reference_full_decrypt =
        aes128_xts_decrypt_reference(
            reference_full,
            reference_full_recovered,
            sizeof(reference_full),
            tweak_input,
            data_round_keys,
            tweak_round_keys
        ) &&
        memcmp(
            reference_full_recovered,
            full_plaintext,
            sizeof(full_plaintext)
        ) == 0;

    int aesni_full_decrypt =
        aes128_xts_decrypt_aesni8(
            aesni_full,
            aesni_full_recovered,
            sizeof(aesni_full),
            tweak_input,
            data_decrypt_keys,
            tweak_encrypt_keys
        ) &&
        memcmp(
            aesni_full_recovered,
            full_plaintext,
            sizeof(full_plaintext)
        ) == 0;

    int reference_partial_decrypt =
        aes128_xts_decrypt_reference(
            reference_partial,
            reference_partial_recovered,
            sizeof(reference_partial),
            tweak_input,
            data_round_keys,
            tweak_round_keys
        ) &&
        memcmp(
            reference_partial_recovered,
            partial_plaintext,
            sizeof(partial_plaintext)
        ) == 0;

    int aesni_partial_decrypt =
        aes128_xts_decrypt_aesni8(
            aesni_partial,
            aesni_partial_recovered,
            sizeof(aesni_partial),
            tweak_input,
            data_decrypt_keys,
            tweak_encrypt_keys
        ) &&
        memcmp(
            aesni_partial_recovered,
            partial_plaintext,
            sizeof(partial_plaintext)
        ) == 0;

    print_hex(
        "Data key K1:",
        combined_key,
        16
    );

    print_hex(
        "Tweak key K2:",
        combined_key + 16,
        16
    );

    print_hex(
        "Tweak input:",
        tweak_input,
        16
    );

    print_hex(
        "Full plaintext block 0:",
        full_plaintext,
        16
    );

    print_hex(
        "OpenSSL ciphertext 0:",
        openssl_full,
        16
    );

    print_hex(
        "Reference ciphertext 0:",
        reference_full,
        16
    );

    print_hex(
        "AES-NI ciphertext 0:",
        aesni_full,
        16
    );

    printf("\n[Correctness results]\n");

    printf(
        "Full reference vs OpenSSL : %s\n",
        full_reference_match ? "PASS" : "FAIL"
    );

    printf(
        "Full AES-NI vs OpenSSL    : %s\n",
        full_aesni_match ? "PASS" : "FAIL"
    );

    printf(
        "CTS reference vs OpenSSL  : %s\n",
        partial_reference_match ? "PASS" : "FAIL"
    );

    printf(
        "CTS AES-NI vs OpenSSL     : %s\n",
        partial_aesni_match ? "PASS" : "FAIL"
    );

    printf(
        "Reference full decrypt    : %s\n",
        reference_full_decrypt ? "PASS" : "FAIL"
    );

    printf(
        "AES-NI full decrypt       : %s\n",
        aesni_full_decrypt ? "PASS" : "FAIL"
    );

    printf(
        "Reference CTS decrypt     : %s\n",
        reference_partial_decrypt ? "PASS" : "FAIL"
    );

    printf(
        "AES-NI CTS decrypt        : %s\n",
        aesni_partial_decrypt ? "PASS" : "FAIL"
    );

    printf(
        "XTS authentication        : NOT PROVIDED\n"
    );

    int all_tests_passed =
        full_reference_match &&
        full_aesni_match &&
        partial_reference_match &&
        partial_aesni_match &&
        reference_full_decrypt &&
        aesni_full_decrypt &&
        reference_partial_decrypt &&
        aesni_partial_decrypt;

    printf(
        "Overall result            : %s\n",
        all_tests_passed
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    return all_tests_passed ? 0 : 1;
}
#endif /* AES_XTS_NO_MAIN */
