#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results

TEMP_RESULT="$(mktemp)"
trap 'rm -f "$TEMP_RESULT"' EXIT

PROGRAMS=(
    "bench_ref"
    "bench_ttable"
    "bench_shuffle"
    "bench_aesni"
    "bench_vaes"
)

echo "Running single-thread AES benchmarks..."
echo "Each implementation uses three timed trials."
echo

for program in "${PROGRAMS[@]}"; do
    echo -n "Testing ${program} ... "

    OUTPUT="$(taskset -c 0 "./bin/${program}")"

    printf '%s\n' "$OUTPUT" \
        > "results/${program}.txt"

    printf '%s\n' "$OUTPUT" \
        | grep '^RESULT|' \
        >> "$TEMP_RESULT"

    MEDIAN="$(
        printf '%s\n' "$OUTPUT" \
        | awk -F'|' '/^RESULT\|/ {print $3}'
    )"

    echo "${MEDIAN} MiB/s"
done

BASE_RATE="$(
    awk -F'|' '$2 == "Reference" {print $3}' \
        "$TEMP_RESULT"
)"

{
    echo
    echo "===== AES-128 BLOCK PERFORMANCE SUMMARY ====="
    echo "Mode          : single thread"
    echo "CPU affinity  : CPU 0"
    echo "Buffer        : 16 MiB"
    echo "Trials        : 3, median reported"
    echo

    printf "%-18s %15s %12s\n" \
        "Implementation" \
        "Median MiB/s" \
        "Speedup"

    printf "%-18s %15s %12s\n" \
        "------------------" \
        "---------------" \
        "------------"

    awk -F'|' -v base="$BASE_RATE" '
        {
            printf "%-18s %15.2f %11.2fx\n",
                   $2, $3, $3 / base
        }
    ' "$TEMP_RESULT"
} | tee results/block_benchmark_summary.txt
