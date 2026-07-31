#define AES_NO_MAIN
#include "aes_aesni.c"
#undef AES_NO_MAIN

static uint8_t benchmark_byte_keys[AES128_ROUND_KEYS_SIZE];
static __m128i benchmark_encrypt_keys[11];
static __m128i benchmark_decrypt_keys[11];

static void bench_setup(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    aes128_key_expand(key, benchmark_byte_keys);

    aesni_prepare_round_keys(
        benchmark_byte_keys,
        benchmark_encrypt_keys,
        benchmark_decrypt_keys
    );
}

static void bench_encrypt_buffer(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    for (size_t offset = 0;
         offset < length;
         offset += AES_BLOCK_SIZE) {

        aes128_encrypt_aesni(
            input + offset,
            output + offset,
            benchmark_encrypt_keys
        );
    }
}

#define BENCH_NAME "AES-NI"
#include "bench_driver.h"
