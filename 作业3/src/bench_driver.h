#ifndef AES_BENCH_DRIVER_H
#define AES_BENCH_DRIVER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef BENCH_NAME
#error "BENCH_NAME must be defined"
#endif

#define BENCH_BUFFER_SIZE (16u * 1024u * 1024u)
#define BENCH_TRIALS 3
#define BENCH_MIN_SECONDS 1.0

/*
 * 每个具体测试文件必须实现：
 *
 * bench_setup()：
 *     完成密钥扩展、查找表初始化等准备工作。
 *
 * bench_encrypt_buffer()：
 *     加密长度为length的缓冲区。
 */
static void bench_setup(void);

static void bench_encrypt_buffer(
    const uint8_t *input,
    uint8_t *output,
    size_t length
);

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

int main(void)
{
    uint8_t *buffer_a = NULL;
    uint8_t *buffer_b = NULL;

    if (posix_memalign(
            (void **)&buffer_a,
            64,
            BENCH_BUFFER_SIZE
        ) != 0 ||
        posix_memalign(
            (void **)&buffer_b,
            64,
            BENCH_BUFFER_SIZE
        ) != 0) {

        fprintf(stderr, "Aligned memory allocation failed.\n");
        free(buffer_a);
        free(buffer_b);
        return EXIT_FAILURE;
    }

    /*
     * 使用确定性数据填充输入，保证每次实验可复现。
     */
    for (size_t i = 0; i < BENCH_BUFFER_SIZE; ++i) {
        buffer_a[i] =
            (uint8_t)((i * 131u + 17u) & 0xffu);
    }

    memset(buffer_b, 0, BENCH_BUFFER_SIZE);

    bench_setup();

    /*
     * 预热：减少首次运行时缓存、页面映射等因素的影响。
     */
    bench_encrypt_buffer(
        buffer_a,
        buffer_b,
        BENCH_BUFFER_SIZE
    );

    uint8_t *source = buffer_b;
    uint8_t *destination = buffer_a;

    double rates[BENCH_TRIALS];

    for (int trial = 0; trial < BENCH_TRIALS; ++trial) {
        size_t passes = 0;
        double start = current_time_seconds();
        double elapsed;

        do {
            bench_encrypt_buffer(
                source,
                destination,
                BENCH_BUFFER_SIZE
            );

            uint8_t *temporary = source;
            source = destination;
            destination = temporary;

            ++passes;
            elapsed = current_time_seconds() - start;
        } while (elapsed < BENCH_MIN_SECONDS);

        double total_mib =
            ((double)passes *
             (double)BENCH_BUFFER_SIZE) /
            (1024.0 * 1024.0);

        rates[trial] = total_mib / elapsed;
    }

    sort_three(rates);

    /*
     * 读取输出数据，防止编译器把计算过程视为无用代码。
     */
    volatile uint64_t checksum = 0;

    for (size_t i = 0;
         i < BENCH_BUFFER_SIZE;
         i += 4096) {

        checksum += source[i];
    }

    checksum += source[BENCH_BUFFER_SIZE - 1];

    printf("===== AES BLOCK BENCHMARK =====\n");
    printf("Implementation : %s\n", BENCH_NAME);
    printf("Buffer size    : 16 MiB\n");
    printf("Timed trials   : %d\n", BENCH_TRIALS);
    printf("Minimum time   : %.1f second per trial\n",
           BENCH_MIN_SECONDS);

    for (int i = 0; i < BENCH_TRIALS; ++i) {
        printf(
            "Sorted result %d : %.2f MiB/s\n",
            i + 1,
            rates[i]
        );
    }

    printf("Median          : %.2f MiB/s\n", rates[1]);
    printf("Checksum        : %llu\n",
           (unsigned long long)checksum);

    /*
     * 供汇总脚本自动读取。
     */
    printf(
        "RESULT|%s|%.2f\n",
        BENCH_NAME,
        rates[1]
    );

    free(buffer_a);
    free(buffer_b);

    return EXIT_SUCCESS;
}

#endif
