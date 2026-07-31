/*
 * 将 aes_xts.c 中原有的 main 函数临时改名，
 * 以便复用其中的 XTS 实现。
 */
#define AES_XTS_NO_MAIN
#include "aes_xts.c"
#undef AES_XTS_NO_MAIN

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define XTS_BENCH_SIZE (16u * 1024u * 1024u)
#define XTS_TRIALS 3
#define XTS_MIN_SECONDS 1.0

typedef void (*xts_benchmark_function)(
    const uint8_t *input,
    uint8_t *output,
    size_t length
);

/*
 * XTS使用两把AES-128密钥：
 *
 * data_key  用于加密数据；
 * tweak_key 用于生成初始tweak。
 */
static const uint8_t benchmark_combined_key[32] = {
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

/*
 * 性能实验中的数据单元编号。
 *
 * 这里只用于可重复的性能测试。
 * 真实磁盘加密中，不同数据单元应使用不同的tweak输入。
 */
static const uint8_t benchmark_tweak_input[16] = {
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x01
};

static uint8_t reference_data_round_keys[
    AES128_ROUND_KEYS_SIZE
];

static uint8_t reference_tweak_round_keys[
    AES128_ROUND_KEYS_SIZE
];

static __m128i aesni_data_encrypt_keys[11];
static __m128i aesni_data_decrypt_keys[11];

static __m128i aesni_tweak_encrypt_keys[11];
static __m128i aesni_tweak_decrypt_keys[11];

static double current_time_seconds(void)
{
    struct timespec now;

    if (clock_gettime(
            CLOCK_MONOTONIC_RAW,
            &now
        ) != 0) {

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
            (uint8_t)((i * 173u + 37u) & 0xffu);
    }
}

/*
 * 基础软件XTS包装函数。
 */
static void benchmark_xts_reference(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    int success =
        aes128_xts_encrypt_reference(
            input,
            output,
            length,
            benchmark_tweak_input,
            reference_data_round_keys,
            reference_tweak_round_keys
        );

    if (!success) {
        fprintf(
            stderr,
            "Reference XTS encryption failed.\n"
        );

        exit(EXIT_FAILURE);
    }
}

/*
 * AES-NI八分组流水线XTS包装函数。
 */
static void benchmark_xts_aesni(
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    int success =
        aes128_xts_encrypt_aesni8(
            input,
            output,
            length,
            benchmark_tweak_input,
            aesni_data_encrypt_keys,
            aesni_tweak_encrypt_keys
        );

    if (!success) {
        fprintf(
            stderr,
            "AES-NI XTS encryption failed.\n"
        );

        exit(EXIT_FAILURE);
    }
}

static double run_one_benchmark(
    const char *name,
    xts_benchmark_function function,
    uint8_t *buffer_a,
    uint8_t *buffer_b)
{
    double rates[XTS_TRIALS];

    fill_test_data(
        buffer_a,
        XTS_BENCH_SIZE
    );

    memset(
        buffer_b,
        0,
        XTS_BENCH_SIZE
    );

    /*
     * 预热一次，减少页面映射、缓存等首次运行因素。
     */
    function(
        buffer_a,
        buffer_b,
        XTS_BENCH_SIZE
    );

    for (int trial = 0;
         trial < XTS_TRIALS;
         ++trial) {

        uint8_t *source = buffer_a;
        uint8_t *destination = buffer_b;

        size_t passes = 0;

        double start =
            current_time_seconds();

        double elapsed;

        do {
            function(
                source,
                destination,
                XTS_BENCH_SIZE
            );

            /*
             * 交换输入和输出缓冲区，
             * 避免每轮重复写入完全相同的位置内容。
             */
            uint8_t *temporary = source;
            source = destination;
            destination = temporary;

            ++passes;

            elapsed =
                current_time_seconds() - start;

        } while (elapsed < XTS_MIN_SECONDS);

        double processed_mib =
            ((double)passes *
             (double)XTS_BENCH_SIZE) /
            (1024.0 * 1024.0);

        rates[trial] =
            processed_mib / elapsed;
    }

    sort_three(rates);

    /*
     * 读取部分输出，防止编译器把计算删除。
     */
    volatile uint64_t checksum = 0;

    for (size_t i = 0;
         i < XTS_BENCH_SIZE;
         i += 4096) {

        checksum += buffer_a[i];
        checksum += buffer_b[i];
    }

    printf("\n[%s]\n", name);

    for (int trial = 0;
         trial < XTS_TRIALS;
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
#if defined(__GNUC__)
    int aes_supported =
        __builtin_cpu_supports("aes") != 0;
#else
    int aes_supported = 1;
#endif

    printf(
        "===== AES-128 XTS PERFORMANCE BENCHMARK =====\n"
    );

    printf(
        "AES-NI support : %s\n",
        aes_supported ? "YES" : "NO"
    );

    printf("Mode           : single thread\n");
    printf("Buffer size    : 16 MiB\n");
    printf("Data length    : complete AES blocks\n");
    printf("Timed trials   : 3\n");
    printf("Reported value : median\n");

    if (!aes_supported) {
        fprintf(
            stderr,
            "AES-NI is unavailable.\n"
        );

        return EXIT_FAILURE;
    }

    /*
     * 生成基础软件版轮密钥。
     */
    aes128_key_expand(
        benchmark_combined_key,
        reference_data_round_keys
    );

    aes128_key_expand(
        benchmark_combined_key + 16,
        reference_tweak_round_keys
    );

    /*
     * 生成AES-NI轮密钥。
     */
    aesni_prepare_round_keys(
        reference_data_round_keys,
        aesni_data_encrypt_keys,
        aesni_data_decrypt_keys
    );

    aesni_prepare_round_keys(
        reference_tweak_round_keys,
        aesni_tweak_encrypt_keys,
        aesni_tweak_decrypt_keys
    );

    /*
     * 正式性能测试前，对4 KiB数据进行交叉验证。
     */
    uint8_t correctness_input[4096];
    uint8_t correctness_reference[4096];
    uint8_t correctness_aesni[4096];
    uint8_t correctness_recovered[4096];

    fill_test_data(
        correctness_input,
        sizeof(correctness_input)
    );

    benchmark_xts_reference(
        correctness_input,
        correctness_reference,
        sizeof(correctness_input)
    );

    benchmark_xts_aesni(
        correctness_input,
        correctness_aesni,
        sizeof(correctness_input)
    );

    int encryption_match =
        memcmp(
            correctness_reference,
            correctness_aesni,
            sizeof(correctness_reference)
        ) == 0;

    int decryption_ok =
        aes128_xts_decrypt_aesni8(
            correctness_aesni,
            correctness_recovered,
            sizeof(correctness_aesni),
            benchmark_tweak_input,
            aesni_data_decrypt_keys,
            aesni_tweak_encrypt_keys
        ) &&
        memcmp(
            correctness_recovered,
            correctness_input,
            sizeof(correctness_input)
        ) == 0;

    printf(
        "Pre-benchmark encryption match: %s\n",
        encryption_match ? "PASS" : "FAIL"
    );

    printf(
        "Pre-benchmark decryption test : %s\n",
        decryption_ok ? "PASS" : "FAIL"
    );

    if (!encryption_match || !decryption_ok) {
        return EXIT_FAILURE;
    }

    uint8_t *buffer_a = NULL;
    uint8_t *buffer_b = NULL;

    if (posix_memalign(
            (void **)&buffer_a,
            64,
            XTS_BENCH_SIZE
        ) != 0 ||
        posix_memalign(
            (void **)&buffer_b,
            64,
            XTS_BENCH_SIZE
        ) != 0) {

        fprintf(
            stderr,
            "Aligned memory allocation failed.\n"
        );

        free(buffer_a);
        free(buffer_b);

        return EXIT_FAILURE;
    }

    double reference_rate =
        run_one_benchmark(
            "Reference XTS",
            benchmark_xts_reference,
            buffer_a,
            buffer_b
        );

    double aesni_rate =
        run_one_benchmark(
            "AES-NI XTS 8-block",
            benchmark_xts_aesni,
            buffer_a,
            buffer_b
        );

    printf(
        "\n===== AES-128 XTS PERFORMANCE SUMMARY =====\n"
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
        "Reference XTS",
        reference_rate,
        1.0
    );

    printf(
        "%-24s %15.2f %11.2fx\n",
        "AES-NI XTS 8-block",
        aesni_rate,
        aesni_rate / reference_rate
    );

    printf(
        "\nOverall result: ALL TESTS PASSED\n"
    );

    free(buffer_a);
    free(buffer_b);

    return EXIT_SUCCESS;
}
