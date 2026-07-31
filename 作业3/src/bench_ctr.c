#define AES_CTR_NO_MAIN
#include "aes_ctr.c"
#undef AES_CTR_NO_MAIN

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CTR_BENCH_SIZE (16u * 1024u * 1024u)
#define CTR_TRIALS 3
#define CTR_MIN_SECONDS 1.0

typedef void (*ctr_benchmark_function)(
    const uint8_t *input,
    uint8_t *output,
    size_t length
);

static uint8_t benchmark_byte_round_keys[
    AES128_ROUND_KEYS_SIZE
];

static __m128i benchmark_round_keys_128[11];
static __m256i benchmark_round_keys_256[11];

static const uint8_t benchmark_counter[16] = {
    0xf0,0xf1,0xf2,0xf3,
    0xf4,0xf5,0xf6,0xf7,
    0xf8,0xf9,0xfa,0xfb,
    0xfc,0xfd,0xfe,0xff
};

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
        double temp = values[0];
        values[0] = values[1];
        values[1] = temp;
    }

    if (values[1] > values[2]) {
        double temp = values[1];
        values[1] = values[2];
        values[2] = temp;
    }

    if (values[0] > values[1]) {
        double temp = values[0];
        values[0] = values[1];
        values[1] = temp;
    }
}

static void fill_test_data(uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        buffer[i] =
            (uint8_t)((i * 131u + 29u) & 0xffu);
    }
}

/* 基础软件 AES-CTR 包装函数 */
static void benchmark_ctr_reference(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    aes128_ctr_reference(
        input,
        output,
        length,
        benchmark_counter,
        benchmark_byte_round_keys
    );
}

/* AES-NI 八分组流水线 CTR 包装函数 */
static void benchmark_ctr_aesni(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    aes128_ctr_aesni8(
        input,
        output,
        length,
        benchmark_counter,
        benchmark_round_keys_128
    );
}

/* VAES 八分组并行 CTR 包装函数 */
static void benchmark_ctr_vaes(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    aes128_ctr_vaes8(
        input,
        output,
        length,
        benchmark_counter,
        benchmark_round_keys_128,
        benchmark_round_keys_256
    );
}

static double run_one_benchmark(
    const char *name,
    ctr_benchmark_function function,
    uint8_t *buffer_a,
    uint8_t *buffer_b)
{
    double rates[CTR_TRIALS];

    fill_test_data(buffer_a, CTR_BENCH_SIZE);
    memset(buffer_b, 0, CTR_BENCH_SIZE);

    /* 预热，减少首次运行和页面映射的影响 */
    function(
        buffer_a,
        buffer_b,
        CTR_BENCH_SIZE
    );

    for (int trial = 0; trial < CTR_TRIALS; ++trial) {
        uint8_t *source = buffer_a;
        uint8_t *destination = buffer_b;

        size_t passes = 0;
        double start = current_time_seconds();
        double elapsed;

        do {
            function(
                source,
                destination,
                CTR_BENCH_SIZE
            );

            uint8_t *temporary = source;
            source = destination;
            destination = temporary;

            ++passes;

            elapsed =
                current_time_seconds() - start;

        } while (elapsed < CTR_MIN_SECONDS);

        double processed_mib =
            ((double)passes *
             (double)CTR_BENCH_SIZE) /
            (1024.0 * 1024.0);

        rates[trial] =
            processed_mib / elapsed;
    }

    sort_three(rates);

    volatile uint64_t checksum = 0;

    for (size_t i = 0;
         i < CTR_BENCH_SIZE;
         i += 4096) {

        checksum += buffer_a[i];
        checksum += buffer_b[i];
    }

    printf("\n[%s]\n", name);

    for (int i = 0; i < CTR_TRIALS; ++i) {
        printf(
            "Sorted result %d : %.2f MiB/s\n",
            i + 1,
            rates[i]
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
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

#if defined(__GNUC__)
    int aes_supported =
        __builtin_cpu_supports("aes") != 0;

    int vaes_supported =
        __builtin_cpu_supports("vaes") != 0;

    int avx2_supported =
        __builtin_cpu_supports("avx2") != 0;
#else
    int aes_supported = 1;
    int vaes_supported = 1;
    int avx2_supported = 1;
#endif

    printf(
        "===== AES-128 CTR PERFORMANCE BENCHMARK =====\n"
    );

    printf(
        "AES-NI support : %s\n",
        aes_supported ? "YES" : "NO"
    );

    printf(
        "VAES support   : %s\n",
        vaes_supported ? "YES" : "NO"
    );

    printf(
        "AVX2 support   : %s\n",
        avx2_supported ? "YES" : "NO"
    );

    printf("Mode           : single thread\n");
    printf("Buffer size    : 16 MiB\n");
    printf("Timed trials   : 3\n");
    printf("Reported value : median\n");

    if (!aes_supported ||
        !vaes_supported ||
        !avx2_supported) {

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
            CTR_BENCH_SIZE
        ) != 0 ||
        posix_memalign(
            (void **)&buffer_b,
            64,
            CTR_BENCH_SIZE
        ) != 0) {

        fprintf(
            stderr,
            "Aligned memory allocation failed.\n"
        );

        free(buffer_a);
        free(buffer_b);

        return EXIT_FAILURE;
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
     * 正式计时前先交叉比较三个实现，
     * 确保它们对同一输入产生完全相同的输出。
     */
    uint8_t correctness_input[1024];
    uint8_t correctness_reference[1024];
    uint8_t correctness_aesni[1024];
    uint8_t correctness_vaes[1024];

    fill_test_data(
        correctness_input,
        sizeof(correctness_input)
    );

    benchmark_ctr_reference(
        correctness_input,
        correctness_reference,
        sizeof(correctness_input)
    );

    benchmark_ctr_aesni(
        correctness_input,
        correctness_aesni,
        sizeof(correctness_input)
    );

    benchmark_ctr_vaes(
        correctness_input,
        correctness_vaes,
        sizeof(correctness_input)
    );

    int correctness_ok =
        memcmp(
            correctness_reference,
            correctness_aesni,
            sizeof(correctness_reference)
        ) == 0 &&
        memcmp(
            correctness_reference,
            correctness_vaes,
            sizeof(correctness_reference)
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
            "Reference CTR",
            benchmark_ctr_reference,
            buffer_a,
            buffer_b
        );

    double aesni_rate =
        run_one_benchmark(
            "AES-NI CTR 8-block",
            benchmark_ctr_aesni,
            buffer_a,
            buffer_b
        );

    double vaes_rate =
        run_one_benchmark(
            "VAES CTR 8-block",
            benchmark_ctr_vaes,
            buffer_a,
            buffer_b
        );

    printf(
        "\n===== AES-128 CTR PERFORMANCE SUMMARY =====\n"
    );

    printf(
        "%-24s %15s %12s\n",
        "Implementation",
        "Median MiB/s",
        "Speedup"
    );

    printf(
        "%-24s %15s %12s\n",
        "------------------------",
        "---------------",
        "------------"
    );

    printf(
        "%-24s %15.2f %11.2fx\n",
        "Reference CTR",
        reference_rate,
        1.0
    );

    printf(
        "%-24s %15.2f %11.2fx\n",
        "AES-NI CTR 8-block",
        aesni_rate,
        aesni_rate / reference_rate
    );

    printf(
        "%-24s %15.2f %11.2fx\n",
        "VAES CTR 8-block",
        vaes_rate,
        vaes_rate / reference_rate
    );

    printf(
        "\nOverall result: ALL TESTS PASSED\n"
    );

    free(buffer_a);
    free(buffer_b);

    _mm256_zeroupper();

    return EXIT_SUCCESS;
}
