#define AES_GCM_NO_MAIN
#include "aes_gcm.c"
#undef AES_GCM_NO_MAIN

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GCM_BENCH_SIZE (2u * 1024u * 1024u)
#define GCM_TRIALS 3
#define GCM_MIN_SECONDS 0.75

static uint8_t benchmark_byte_round_keys[
    AES128_ROUND_KEYS_SIZE
];

static __m128i benchmark_round_keys_128[11];
static __m256i benchmark_round_keys_256[11];

static uint8_t benchmark_aad[32];

static double current_time_seconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return (double)now.tv_sec +
           (double)now.tv_nsec / 1000000000.0;
}

static void sort_three(double values[3])
{
    if (values[0] > values[1]) {
        double temporary = values[0];
        values[0] = values[1];
        values[1] = temporary;
    }

    if (values[1] > values[2]) {
        double temporary = values[1];
        values[1] = values[2];
        values[2] = temporary;
    }

    if (values[0] > values[1]) {
        double temporary = values[0];
        values[0] = values[1];
        values[1] = temporary;
    }
}

static void fill_test_data(
    uint8_t *buffer,
    size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        buffer[i] =
            (uint8_t)((i * 157u + 43u) & 0xffu);
    }
}

/*
 * 为每次性能测试调用生成不同的96位IV。
 *
 * 前8字节固定，后4字节使用调用编号。
 */
static void make_iv(
    uint8_t iv[12],
    uint32_t invocation)
{
    static const uint8_t prefix[8] = {
        0x47, 0x43, 0x4d, 0x2d,
        0x42, 0x45, 0x4e, 0x43
    };

    memcpy(iv, prefix, 8);

    iv[8]  = (uint8_t)(invocation >> 24);
    iv[9]  = (uint8_t)(invocation >> 16);
    iv[10] = (uint8_t)(invocation >> 8);
    iv[11] = (uint8_t)invocation;
}

static double run_one_benchmark(
    const char *name,
    gf128_multiply_function multiply,
    uint8_t *buffer_a,
    uint8_t *buffer_b)
{
    double rates[GCM_TRIALS];
    uint8_t final_tag[16] = {0};

    fill_test_data(
        buffer_a,
        GCM_BENCH_SIZE
    );

    memset(
        buffer_b,
        0,
        GCM_BENCH_SIZE
    );

    /*
     * 预热运行。
     */
    {
        uint8_t warmup_iv[12];

        make_iv(warmup_iv, 1);

        aes128_gcm_encrypt(
            buffer_a,
            GCM_BENCH_SIZE,
            benchmark_aad,
            sizeof(benchmark_aad),
            warmup_iv,
            buffer_b,
            final_tag,
            benchmark_round_keys_128,
            multiply
        );
    }

    for (int trial = 0;
         trial < GCM_TRIALS;
         ++trial) {

        uint8_t *source = buffer_a;
        uint8_t *destination = buffer_b;

        size_t passes = 0;

        double start =
            current_time_seconds();

        double elapsed;

        do {
            uint8_t iv[12];

            uint32_t invocation =
                (uint32_t)(
                    trial * 1000000u +
                    passes +
                    2u
                );

            make_iv(iv, invocation);

            aes128_gcm_encrypt(
                source,
                GCM_BENCH_SIZE,
                benchmark_aad,
                sizeof(benchmark_aad),
                iv,
                destination,
                final_tag,
                benchmark_round_keys_128,
                multiply
            );

            uint8_t *temporary = source;
            source = destination;
            destination = temporary;

            ++passes;

            elapsed =
                current_time_seconds() - start;

        } while (elapsed < GCM_MIN_SECONDS);

        double processed_mib =
            ((double)passes *
             (double)GCM_BENCH_SIZE) /
            (1024.0 * 1024.0);

        rates[trial] =
            processed_mib / elapsed;
    }

    sort_three(rates);

    volatile uint64_t checksum = 0;

    for (size_t i = 0;
         i < GCM_BENCH_SIZE;
         i += 4096) {

        checksum += buffer_a[i];
        checksum += buffer_b[i];
    }

    for (int i = 0; i < 16; ++i) {
        checksum += final_tag[i];
    }

    printf("\n[%s]\n", name);

    for (int trial = 0;
         trial < GCM_TRIALS;
         ++trial) {

        printf(
            "Sorted result %d : %.2f MiB/s\n",
            trial + 1,
            rates[trial]
        );
    }

    printf(
        "Median          : %.2f MiB/s\n",
        rates[1]
    );

    printf(
        "Checksum        : %llu\n",
        (unsigned long long)checksum
    );

    return rates[1];
}

int main(void)
{
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

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
        "===== AES-128 GCM PERFORMANCE BENCHMARK =====\n"
    );

    printf(
        "AES-NI support : %s\n",
        aes_supported ? "YES" : "NO"
    );

    printf(
        "PCLMUL support : %s\n",
        pclmul_supported ? "YES" : "NO"
    );

    printf(
        "SSSE3 support  : %s\n",
        ssse3_supported ? "YES" : "NO"
    );

    printf("Mode           : single thread\n");
    printf("Buffer size    : 2 MiB\n");
    printf("AAD size       : 32 bytes\n");
    printf("Timed trials   : 3\n");
    printf("Reported value : median\n");

    if (!aes_supported ||
        !pclmul_supported ||
        !ssse3_supported) {

        fprintf(
            stderr,
            "Required instruction set is unavailable.\n"
        );

        return EXIT_FAILURE;
    }

    uint8_t *buffer_a = NULL;
    uint8_t *buffer_b = NULL;

    if (posix_memalign(
            (void **)&buffer_a,
            64,
            GCM_BENCH_SIZE
        ) != 0 ||
        posix_memalign(
            (void **)&buffer_b,
            64,
            GCM_BENCH_SIZE
        ) != 0) {

        fprintf(
            stderr,
            "Aligned memory allocation failed.\n"
        );

        free(buffer_a);
        free(buffer_b);

        return EXIT_FAILURE;
    }

    for (size_t i = 0;
         i < sizeof(benchmark_aad);
         ++i) {

        benchmark_aad[i] =
            (uint8_t)(i * 11u + 5u);
    }

    aes128_key_expand(
        key,
        benchmark_byte_round_keys
    );

    prepare_encrypt_keys(
        benchmark_byte_round_keys,
        benchmark_round_keys_128,
        benchmark_round_keys_256
    );

    /*
     * 正式计时前，先对4 KiB输入进行交叉验证。
     */
    uint8_t correctness_input[4096];
    uint8_t correctness_reference[4096];
    uint8_t correctness_pclmul[4096];

    uint8_t reference_tag[16];
    uint8_t pclmul_tag[16];

    uint8_t correctness_iv[12];

    fill_test_data(
        correctness_input,
        sizeof(correctness_input)
    );

    make_iv(correctness_iv, 0);

    aes128_gcm_encrypt(
        correctness_input,
        sizeof(correctness_input),
        benchmark_aad,
        sizeof(benchmark_aad),
        correctness_iv,
        correctness_reference,
        reference_tag,
        benchmark_round_keys_128,
        gf128_multiply_reference
    );

    aes128_gcm_encrypt(
        correctness_input,
        sizeof(correctness_input),
        benchmark_aad,
        sizeof(benchmark_aad),
        correctness_iv,
        correctness_pclmul,
        pclmul_tag,
        benchmark_round_keys_128,
        gf128_multiply_pclmul
    );

    int correctness_ok =
        memcmp(
            correctness_reference,
            correctness_pclmul,
            sizeof(correctness_reference)
        ) == 0 &&
        memcmp(
            reference_tag,
            pclmul_tag,
            sizeof(reference_tag)
        ) == 0;

    printf(
        "Pre-benchmark correctness: %s\n",
        correctness_ok ? "PASS" : "FAIL"
    );

    if (!correctness_ok) {
        free(buffer_a);
        free(buffer_b);
        return EXIT_FAILURE;
    }

    double reference_rate =
        run_one_benchmark(
            "AES-NI + reference GHASH",
            gf128_multiply_reference,
            buffer_a,
            buffer_b
        );

    double pclmul_rate =
        run_one_benchmark(
            "AES-NI + PCLMUL GHASH",
            gf128_multiply_pclmul,
            buffer_a,
            buffer_b
        );

    printf(
        "\n===== AES-128 GCM PERFORMANCE SUMMARY =====\n"
    );

    printf(
        "%-28s %15s %12s\n",
        "Implementation",
        "Median MiB/s",
        "Speedup"
    );

    printf(
        "%-28s %15s %12s\n",
        "----------------------------",
        "---------------",
        "------------"
    );

    printf(
        "%-28s %15.2f %11.2fx\n",
        "Reference GHASH",
        reference_rate,
        1.0
    );

    printf(
        "%-28s %15.2f %11.2fx\n",
        "PCLMUL GHASH",
        pclmul_rate,
        pclmul_rate / reference_rate
    );

    printf(
        "\nOverall result: ALL TESTS PASSED\n"
    );

    free(buffer_a);
    free(buffer_b);

    _mm256_zeroupper();

    return EXIT_SUCCESS;
}
