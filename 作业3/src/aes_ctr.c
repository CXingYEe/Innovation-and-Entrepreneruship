#define AES_NO_MAIN
#include "aes_ref.c"
#undef AES_NO_MAIN

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void prepare_encrypt_keys(
    const uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE],
    __m128i round_keys_128[11],
    __m256i round_keys_256[11])
{
    for (int round = 0; round <= 10; ++round) {
        round_keys_128[round] =
            _mm_loadu_si128(
                (const __m128i *)
                (byte_round_keys + 16 * round)
            );

        round_keys_256[round] =
            _mm256_broadcastsi128_si256(
                round_keys_128[round]
            );
    }
}

/*
 * 将128位大端计数器加1。
 */
static void increment_counter_be(uint8_t counter[16])
{
    for (int i = 15; i >= 0; --i) {
        counter[i]++;

        if (counter[i] != 0) {
            break;
        }
    }
}

static __m128i encrypt_state_aesni(
    __m128i state,
    const __m128i round_keys[11])
{
    state = _mm_xor_si128(state, round_keys[0]);

    for (int round = 1; round < 10; ++round) {
        state = _mm_aesenc_si128(
            state,
            round_keys[round]
        );
    }

    return _mm_aesenclast_si128(
        state,
        round_keys[10]
    );
}

/*
 * AES-NI同时保持8个独立分组在流水线中。
 */
static void encrypt_8blocks_aesni(
    const uint8_t input[128],
    uint8_t output[128],
    const __m128i round_keys[11])
{
    __m128i state[8];

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_loadu_si128(
            (const __m128i *)(input + 16 * i)
        );

        state[i] =
            _mm_xor_si128(state[i], round_keys[0]);
    }

    for (int round = 1; round < 10; ++round) {
        for (int i = 0; i < 8; ++i) {
            state[i] = _mm_aesenc_si128(
                state[i],
                round_keys[round]
            );
        }
    }

    for (int i = 0; i < 8; ++i) {
        state[i] = _mm_aesenclast_si128(
            state[i],
            round_keys[10]
        );

        _mm_storeu_si128(
            (__m128i *)(output + 16 * i),
            state[i]
        );
    }
}

/*
 * 四个256位寄存器共处理8个AES分组。
 */
static void encrypt_8blocks_vaes(
    const uint8_t input[128],
    uint8_t output[128],
    const __m256i round_keys[11])
{
    __m256i state0 =
        _mm256_loadu_si256(
            (const __m256i *)(input)
        );

    __m256i state1 =
        _mm256_loadu_si256(
            (const __m256i *)(input + 32)
        );

    __m256i state2 =
        _mm256_loadu_si256(
            (const __m256i *)(input + 64)
        );

    __m256i state3 =
        _mm256_loadu_si256(
            (const __m256i *)(input + 96)
        );

    state0 = _mm256_xor_si256(state0, round_keys[0]);
    state1 = _mm256_xor_si256(state1, round_keys[0]);
    state2 = _mm256_xor_si256(state2, round_keys[0]);
    state3 = _mm256_xor_si256(state3, round_keys[0]);

    for (int round = 1; round < 10; ++round) {
        state0 = _mm256_aesenc_epi128(
            state0,
            round_keys[round]
        );

        state1 = _mm256_aesenc_epi128(
            state1,
            round_keys[round]
        );

        state2 = _mm256_aesenc_epi128(
            state2,
            round_keys[round]
        );

        state3 = _mm256_aesenc_epi128(
            state3,
            round_keys[round]
        );
    }

    state0 = _mm256_aesenclast_epi128(
        state0,
        round_keys[10]
    );

    state1 = _mm256_aesenclast_epi128(
        state1,
        round_keys[10]
    );

    state2 = _mm256_aesenclast_epi128(
        state2,
        round_keys[10]
    );

    state3 = _mm256_aesenclast_epi128(
        state3,
        round_keys[10]
    );

    _mm256_storeu_si256(
        (__m256i *)(output),
        state0
    );

    _mm256_storeu_si256(
        (__m256i *)(output + 32),
        state1
    );

    _mm256_storeu_si256(
        (__m256i *)(output + 64),
        state2
    );

    _mm256_storeu_si256(
        (__m256i *)(output + 96),
        state3
    );
}

/*
 * 基础软件AES实现的CTR模式。
 */
static void aes128_ctr_reference(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t initial_counter[16],
    const uint8_t round_keys[AES128_ROUND_KEYS_SIZE])
{
    uint8_t counter[16];
    uint8_t key_stream[16];

    memcpy(counter, initial_counter, 16);

    while (length > 0) {
        aes128_encrypt_ref(
            counter,
            key_stream,
            round_keys
        );

        size_t count =
            length < 16 ? length : 16;

        for (size_t i = 0; i < count; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += count;
        output += count;
        length -= count;

        increment_counter_be(counter);
    }
}

/*
 * AES-NI八分组流水线CTR。
 */
static void aes128_ctr_aesni8(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t initial_counter[16],
    const __m128i round_keys[11])
{
    uint8_t counter[16];
    uint8_t counters[128];
    uint8_t key_stream[128];

    memcpy(counter, initial_counter, 16);

    while (length >= 128) {
        for (int block = 0; block < 8; ++block) {
            memcpy(
                counters + block * 16,
                counter,
                16
            );

            increment_counter_be(counter);
        }

        encrypt_8blocks_aesni(
            counters,
            key_stream,
            round_keys
        );

        for (int i = 0; i < 128; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += 128;
        output += 128;
        length -= 128;
    }

    while (length > 0) {
        __m128i state =
            _mm_loadu_si128(
                (const __m128i *)counter
            );

        state = encrypt_state_aesni(
            state,
            round_keys
        );

        _mm_storeu_si128(
            (__m128i *)key_stream,
            state
        );

        size_t count =
            length < 16 ? length : 16;

        for (size_t i = 0; i < count; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += count;
        output += count;
        length -= count;

        increment_counter_be(counter);
    }
}

/*
 * VAES八分组并行CTR。
 */
static void aes128_ctr_vaes8(
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    const uint8_t initial_counter[16],
    const __m128i round_keys_128[11],
    const __m256i round_keys_256[11])
{
    uint8_t counter[16];
    uint8_t counters[128];
    uint8_t key_stream[128];

    memcpy(counter, initial_counter, 16);

    while (length >= 128) {
        for (int block = 0; block < 8; ++block) {
            memcpy(
                counters + block * 16,
                counter,
                16
            );

            increment_counter_be(counter);
        }

        encrypt_8blocks_vaes(
            counters,
            key_stream,
            round_keys_256
        );

        for (int i = 0; i < 128; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += 128;
        output += 128;
        length -= 128;
    }

    while (length > 0) {
        __m128i state =
            _mm_loadu_si128(
                (const __m128i *)counter
            );

        state = encrypt_state_aesni(
            state,
            round_keys_128
        );

        _mm_storeu_si128(
            (__m128i *)key_stream,
            state
        );

        size_t count =
            length < 16 ? length : 16;

        for (size_t i = 0; i < count; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += count;
        output += count;
        length -= count;

        increment_counter_be(counter);
    }

    _mm256_zeroupper();
}

#ifndef AES_CTR_NO_MAIN
int main(void)
{
    /*
     * NIST SP 800-38A AES-128 CTR测试向量。
     */
    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

    const uint8_t initial_counter[16] = {
        0xf0,0xf1,0xf2,0xf3,
        0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,
        0xfc,0xfd,0xfe,0xff
    };

    const uint8_t plaintext[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };

    const uint8_t expected_ciphertext[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
        0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
        0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
        0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };

    uint8_t byte_round_keys[AES128_ROUND_KEYS_SIZE];
    __m128i round_keys_128[11];
    __m256i round_keys_256[11];

    uint8_t result_reference[64];
    uint8_t result_aesni[64];
    uint8_t result_vaes[64];
    uint8_t recovered[64];

    aes128_key_expand(key, byte_round_keys);

    prepare_encrypt_keys(
        byte_round_keys,
        round_keys_128,
        round_keys_256
    );

    aes128_ctr_reference(
        plaintext,
        result_reference,
        sizeof(plaintext),
        initial_counter,
        byte_round_keys
    );

    aes128_ctr_aesni8(
        plaintext,
        result_aesni,
        sizeof(plaintext),
        initial_counter,
        round_keys_128
    );

    aes128_ctr_vaes8(
        plaintext,
        result_vaes,
        sizeof(plaintext),
        initial_counter,
        round_keys_128,
        round_keys_256
    );

    /*
     * CTR解密与加密调用完全相同。
     */
    aes128_ctr_vaes8(
        result_vaes,
        recovered,
        sizeof(result_vaes),
        initial_counter,
        round_keys_128,
        round_keys_256
    );

    int reference_ok =
        memcmp(
            result_reference,
            expected_ciphertext,
            64
        ) == 0;

    int aesni_ok =
        memcmp(
            result_aesni,
            expected_ciphertext,
            64
        ) == 0;

    int vaes_ok =
        memcmp(
            result_vaes,
            expected_ciphertext,
            64
        ) == 0;

    int decrypt_ok =
        memcmp(
            recovered,
            plaintext,
            64
        ) == 0;

    printf("===== AES-128 CTR MODE TEST =====\n");

    print_hex("Key:", key, 16);
    print_hex("Initial counter:", initial_counter, 16);
    print_hex("Plaintext block 0:", plaintext, 16);

    print_hex(
        "Expected block 0:",
        expected_ciphertext,
        16
    );

    print_hex(
        "Reference block 0:",
        result_reference,
        16
    );

    print_hex(
        "AES-NI block 0:",
        result_aesni,
        16
    );

    print_hex(
        "VAES block 0:",
        result_vaes,
        16
    );

    printf("\nReference CTR KAT : %s\n",
           reference_ok ? "PASS" : "FAIL");

    printf("AES-NI CTR KAT    : %s\n",
           aesni_ok ? "PASS" : "FAIL");

    printf("VAES CTR KAT      : %s\n",
           vaes_ok ? "PASS" : "FAIL");

    printf("CTR decrypt test  : %s\n",
           decrypt_ok ? "PASS" : "FAIL");

    printf("All 64 bytes match: %s\n",
           reference_ok && aesni_ok && vaes_ok
               ? "YES"
               : "NO");

    printf(
        "Overall result     : %s\n",
        reference_ok &&
        aesni_ok &&
        vaes_ok &&
        decrypt_ok
            ? "ALL TESTS PASSED"
            : "TEST FAILED"
    );

    return reference_ok &&
           aesni_ok &&
           vaes_ok &&
           decrypt_ok
               ? 0
               : 1;
}
#endif
