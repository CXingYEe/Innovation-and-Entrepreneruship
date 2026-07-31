#!/usr/bin/env bash

set -uo pipefail
cd "$(dirname "$0")"

FAILURES=0

check_test() {
    local name="$1"
    local program="$2"

    if [[ ! -x "$program" ]]; then
        echo "[MISSING] $name -> $program"
        FAILURES=$((FAILURES + 1))
        return
    fi

    local output
    output="$("$program" 2>&1)"
    local status=$?

    if [[ $status -eq 0 ]] &&
       grep -q "ALL TESTS PASSED" <<< "$output"; then
        echo "[PASS] $name"
    else
        echo "[FAIL] $name"
        FAILURES=$((FAILURES + 1))
    fi
}

check_instruction() {
    local name="$1"
    local program="$2"
    local pattern="$3"
    local disassembly

    if [[ ! -x "$program" ]]; then
        echo "[MISSING] $name -> $program"
        FAILURES=$((FAILURES + 1))
        return
    fi

    disassembly="$(
        objdump -d -M intel "$program" 2>/dev/null
    )"

    if grep -Eiq "$pattern" <<< "$disassembly"; then
        echo "[PASS] $name instruction evidence"
    else
        echo "[FAIL] $name instruction evidence"
        FAILURES=$((FAILURES + 1))
    fi
}

check_result_file() {
    local name="$1"
    local file="$2"
    local pattern="$3"

    if [[ -f "$file" ]] &&
       grep -q "$pattern" "$file"; then
        echo "[PASS] $name result file"
    else
        echo "[MISSING] $name result file"
        FAILURES=$((FAILURES + 1))
    fi
}

echo "===== HOMEWORK 3 FINAL CHECK ====="
echo

echo "----- Correctness tests -----"

check_test \
    "Reference AES" \
    "bin/aes_ref_test"

check_test \
    "T-table AES" \
    "bin/aes_ttable_test"

check_test \
    "Shuffle AES" \
    "bin/aes_shuffle_test"

check_test \
    "AES-NI AES" \
    "bin/aes_aesni_test"

check_test \
    "VAES AES" \
    "bin/aes_vaes_test"

check_test \
    "CTR mode" \
    "bin/aes_ctr_test"

check_test \
    "GCM mode" \
    "bin/aes_gcm_test"

check_test \
    "XTS mode" \
    "bin/aes_xts_test"

echo
echo "----- Instruction evidence -----"

check_instruction \
    "Shuffle/SSSE3" \
    "bin/aes_shuffle_test" \
    '[[:space:]]v?pshufb[[:space:]]'

check_instruction \
    "AES-NI encryption" \
    "bin/aes_aesni_test" \
    '[[:space:]]aesenc[[:space:]]'

check_instruction \
    "AES-NI decryption" \
    "bin/aes_aesni_test" \
    '[[:space:]]aesdec[[:space:]]'

check_instruction \
    "VAES encryption" \
    "bin/aes_vaes_test" \
    '[[:space:]]vaesenc[[:space:]]'

check_instruction \
    "VAES decryption" \
    "bin/aes_vaes_test" \
    '[[:space:]]vaesdec[[:space:]]'

check_instruction \
    "PCLMUL/GHASH" \
    "bin/aes_gcm_test" \
    '[[:space:]]v?pclmul[[:alnum:]_]*[[:space:]]'

echo
echo "----- Performance result files -----"

check_result_file \
    "AES block benchmark" \
    "results/block_benchmark_summary.txt" \
    "VAES-AVX2"

check_result_file \
    "CTR benchmark" \
    "results/ctr_benchmark.txt" \
    "ALL TESTS PASSED"

check_result_file \
    "GCM benchmark" \
    "results/gcm_benchmark.txt" \
    "ALL TESTS PASSED"

check_result_file \
    "XTS benchmark" \
    "results/xts_benchmark.txt" \
    "ALL TESTS PASSED"

echo
echo "----- Source files -----"

SOURCE_COUNT="$(
    find src -maxdepth 1 -type f \
        \( -name '*.c' -o -name '*.h' \) |
    wc -l
)"

echo "Source files found: $SOURCE_COUNT"

echo

if [[ $FAILURES -eq 0 ]]; then
    echo "FINAL STATUS: ALL REQUIRED TESTS PASSED"
    exit 0
else
    echo "FINAL STATUS: $FAILURES CHECK(S) FAILED"
    exit 1
fi
