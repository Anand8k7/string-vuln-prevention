#!/usr/bin/env bash
# =============================================================================
#  collect_outputs.sh - Run every command shown in the report and save the
#  REAL output to docs/report/outputs/*.txt
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#
#  Usage (from the repository root):
#      bash docs/report/collect_outputs.sh
#      python3 docs/report/render_report.py     # copies outputs into report.md
# =============================================================================
set -u
cd "$(dirname "$0")/../.." || exit 1
ulimit -c 0 2>/dev/null || true

OUT=docs/report/outputs
mkdir -p "$OUT"
rm -f "$OUT"/*.txt

A15=AAAAAAAAAAAAAAA
A16=AAAAAAAAAAAAAAAA
A20=AAAAAAAAAAAAAAAAAAAA
export A15 A16 A20

# run FILE "command" ["command" ...]
#   Appends "$ command", its combined output and the exit code to FILE.
run() {
    local file="$OUT/$1"; shift
    local cmd rc
    for cmd in "$@"; do
        {
            echo "\$ $cmd"
            ( bash -c "$cmd" 2>&1; exit $? ) 2>/dev/null
            rc=$?
            echo "[exit code: $rc]"
            echo
        } >> "$file"
    done
}

# ---------------------------------------------------------------- environment
run 00_environment.txt \
    "uname -sr" \
    "gcc --version | head -n1" \
    "cppcheck --version" \
    "valgrind --version" \
    "make --version | head -n1"

# ---------------------------------------------------------------- build
make clean >/dev/null 2>&1
run 01_build.txt "make all asan"

# ---------------------------------------------------------------- unit tests
make test >/dev/null 2>&1   # builds bin/tests/* (output captured below)
run 02_unit_safe_string.txt   "./bin/tests/test_safe_string"
run 03_unit_input_handler.txt "./bin/tests/test_input_handler"
sed -i '/^TF_RESULT /d' "$OUT"/02_unit_safe_string.txt "$OUT"/03_unit_input_handler.txt

# ---------------------------------------------------------------- Q1
run q1_01_vuln_runs.txt \
    "./bin/vulnerable/q1_overflow alice cse" \
    "./bin/vulnerable/q1_overflow \$A15 cse" \
    "./bin/vulnerable/q1_overflow \$A16 cse" \
    "./bin/vulnerable/q1_overflow \$A20 cse" \
    "./bin/vulnerable/q1_overflow abcdefghijklmno abcdefghijklmno" \
    "./bin/vulnerable/q1_overflow \$(printf 'A%.0s' {1..100}) cse"

run q1_02_asan_path_overflow.txt \
    "./bin/asan/vulnerable_q1_overflow abcdefghijklmno abcdefghijklmno"

run q1_03_asan_intra_struct.txt \
    "./bin/asan/vulnerable_q1_overflow \$A20 cse"

run q1_04_valgrind_ret_overwrite.txt \
    "valgrind -q ./bin/vulnerable/q1_overflow \$(printf 'A%.0s' {1..100}) cse 2>&1 | head -n 18"

run q1_05_secure_runs.txt \
    "./bin/secure/q1_overflow alice cse" \
    "./bin/secure/q1_overflow \$A15 cse" \
    "./bin/secure/q1_overflow \$A16 cse" \
    "./bin/secure/q1_overflow \$A20 cse" \
    "./bin/secure/q1_overflow abcdefghijklmno abcdefghijklmno" \
    "./bin/secure/q1_overflow 'bob;ls' cse" \
    "./bin/secure/q1_overflow '' cse" \
    "./bin/secure/q1_overflow \$(printf 'A%.0s' {1..100}) cse"

run q1_06_asan_secure.txt \
    "./bin/asan/secure_q1_overflow abcdefghijklmno abcdefghijklmno" \
    "./bin/asan/secure_q1_overflow \$(printf 'A%.0s' {1..5000}) cse"

run q1_07_tests.txt "bash tests/scenarios/q1_overflow.sh | grep -v '^TF_RESULT'"

# Hardened build of the SAME vulnerable code: glibc FORTIFY_SOURCE stops it.
run q1_08_fortify.txt \
    "gcc -std=c11 -O2 -D_FORTIFY_SOURCE=2 src/vulnerable/q1_overflow.c -o bin/q1_overflow_fortify" \
    "./bin/q1_overflow_fortify \$A16 cse"

# Negative control: put the VULNERABLE binary where the secure one should be
# and check that the test suites notice (they must fail). Restored afterwards.
negative_control() {
    local prog="$1"
    cp "bin/secure/$prog" "bin/secure/$prog.bak"
    cp "bin/vulnerable/$prog" "bin/secure/$prog"
    run "$2" "bash tests/scenarios/$prog.sh | grep '^Summary'"
    mv "bin/secure/$prog.bak" "bin/secure/$prog"
}
negative_control q1_overflow q1_09_negative_control.txt

# ---------------------------------------------------------------- Q2
run q2_01_compile_warnings.txt \
    "gcc -std=c11 -Wall -Wextra -O2 -c -o /dev/null src/vulnerable/q2_format.c"

run q2_02_vuln_format.txt \
    "printf 'alice\n21\nhello\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n21\n%%p.%%p.%%p.%%p\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n21\n%%27\$lx\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n21\n50%%off\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n21\n%%s%%s%%s%%s%%s%%s%%s%%s\n' | ./bin/vulnerable/q2_format"

run q2_03_vuln_validation.txt \
    "printf 'alice\nabc\nhello\n' | ./bin/vulnerable/q2_format" \
    "printf 'John Smith\n21\nhello\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n-5\nhello\n' | ./bin/vulnerable/q2_format" \
    "printf 'alice\n99999999999999999999\nhello\n' | ./bin/vulnerable/q2_format" \
    "printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n21\nhello\n' | ./bin/vulnerable/q2_format"

run q2_04_asan_record_overflow.txt \
    "printf 'alice\n21\n%s\n' \$(printf 'B%.0s' {1..60}) | ./bin/asan/vulnerable_q2_format 2>&1 | head -n 25"

run q2_05_secure_runs.txt \
    "printf 'alice\n21\nhello\n' | ./bin/secure/q2_format" \
    "printf 'John Smith\n21\nGreat course, 10/10!\n' | ./bin/secure/q2_format" \
    "printf 'alice\n21\n%%p.%%p.%%p.%%p\n' | ./bin/secure/q2_format" \
    "printf 'alice\n21\n%%27\$lx\n' | ./bin/secure/q2_format" \
    "printf 'alice\n21\n%%s%%s%%s%%s%%s%%s%%s%%s\n' | ./bin/secure/q2_format" \
    "printf 'alice\nabc\nhello\n' | ./bin/secure/q2_format" \
    "printf 'alice\n-5\nhello\n' | ./bin/secure/q2_format" \
    "printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n21\nhello\n' | ./bin/secure/q2_format" \
    "printf 'abcdefghijklmno\n120\n%s\n' \$(printf 'B%.0s' {1..40}) | ./bin/secure/q2_format"

run q2_06_tests.txt "bash tests/scenarios/q2_format.sh | grep -v '^TF_RESULT'"
negative_control q2_format q2_07_negative_control.txt

# ---------------------------------------------------------------- whole project
run 90_make_test_summary.txt "make test 2>&1 | tail -n 11"
run 91_analysis.txt "bash analysis/run_analysis.sh"
run 92_cppcheck_vulnerable.txt \
    "cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem --suppress=checkersReport -Isrc/lib -q src/vulnerable"
run 93_cppcheck_secure.txt \
    "cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem --suppress=checkersReport -Isrc/lib -q src/secure src/lib tests"

# Strip the absolute repository path from any output, keep it relative.
sed -i "s#$(pwd)/##g" "$OUT"/*.txt

echo "Saved $(ls "$OUT"/*.txt | wc -l) output files in $OUT/"
