#!/usr/bin/env bash
# =============================================================================
#  run_analysis.sh - Static + dynamic analysis of vulnerable vs secure code
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#  Module 4 (Vulnerability Detection / Analysis)
#
#  Steps (each writes logs into analysis/logs/):
#    1. Compiler warnings  gcc -Wall -Wextra -Wformat=2 ... on both versions
#    2. Cppcheck           static analysis, --enable=all
#    3. Banned-API scan    analysis/banned_functions.py (strcpy, sprintf, ...)
#    4. AddressSanitizer   attack-style inputs against the ASan builds
#    5. Valgrind memcheck  the same inputs against the normal builds
#  Finally a summary table is printed and saved to analysis/logs/summary.txt.
#
#  Usage:   make analyze          (builds everything, then runs this script)
#  Exit:    0 if the SECURE code is clean in every step, 1 otherwise.
#           Findings in the vulnerable code are expected and do not fail.
# =============================================================================
set -u
ulimit -c 0 2>/dev/null || true   # no core / vgcore dump files from expected crashes
cd "$(dirname "$0")/.." || exit 1

LOG=analysis/logs
mkdir -p "$LOG"
rm -f "$LOG"/*.log "$LOG"/summary.txt

SECURE_OK=1                  # becomes 0 on any finding in secure code
declare -a SUMMARY=()        # rows for the final table

have() { command -v "$1" >/dev/null 2>&1; }
row()  { SUMMARY+=("$(printf '| %-30.30s | %-26.26s | %-26.26s |' "$1" "$2" "$3")"); }
hr()   { echo "+--------------------------------+----------------------------+----------------------------+"; }
banner() { echo; echo "==================== $* ===================="; }

for b in bin/vulnerable/q1_overflow bin/vulnerable/q2_format \
         bin/secure/q1_overflow bin/secure/q2_format \
         bin/asan/vulnerable_q1_overflow bin/asan/vulnerable_q2_format \
         bin/asan/secure_q1_overflow bin/asan/secure_q2_format; do
    [ -x "$b" ] || { echo "Missing $b - run 'make all asan' first." >&2; exit 1; }
done

{
    echo "Analysis run: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Host:         $(uname -sr)"
    echo "gcc:          $(gcc --version | head -n1)"
    if have cppcheck; then echo "cppcheck:     $(cppcheck --version)"; fi
    if have valgrind; then echo "valgrind:     $(valgrind --version)"; fi
} | tee "$LOG/environment.log"

# -----------------------------------------------------------------------------
# 1. Compiler warnings (same warning set for both, no -Werror)
# -----------------------------------------------------------------------------
banner "1. Compiler warnings (gcc -Wall -Wextra -Wformat=2 ...)"
WFLAGS="-std=c11 -Wall -Wextra -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wstringop-overflow=4 -O2 -Isrc/lib -c -o /dev/null"
count_warn() { grep -c 'warning:' "$1" || true; }

: > "$LOG/compiler_vulnerable.log"
for f in src/vulnerable/*.c; do
    echo "### $f" >> "$LOG/compiler_vulnerable.log"
    # shellcheck disable=SC2086
    gcc $WFLAGS "$f" >> "$LOG/compiler_vulnerable.log" 2>&1
done
: > "$LOG/compiler_secure.log"
for f in src/secure/*.c src/lib/*.c; do
    echo "### $f" >> "$LOG/compiler_secure.log"
    # shellcheck disable=SC2086
    gcc $WFLAGS "$f" >> "$LOG/compiler_secure.log" 2>&1
done
cv=$(count_warn "$LOG/compiler_vulnerable.log"); cs=$(count_warn "$LOG/compiler_secure.log")
grep 'warning:' "$LOG/compiler_vulnerable.log" | sed 's/^/  vulnerable: /'
echo "vulnerable: $cv warning(s)   secure+lib: $cs warning(s)"
[ "$cs" -eq 0 ] || SECURE_OK=0
row "gcc warnings" "$cv warning(s)" "$cs warning(s)"

# -----------------------------------------------------------------------------
# 2. Cppcheck
# -----------------------------------------------------------------------------
banner "2. Cppcheck (static analysis, --enable=all)"
if have cppcheck; then
    CPPCHECK=(cppcheck --enable=all --std=c11 --inline-suppr
              --suppress=missingIncludeSystem --suppress=checkersReport
              -Isrc/lib --template='{file}:{line}: {severity}: {message} [{id}]' -q)
    "${CPPCHECK[@]}" src/vulnerable > "$LOG/cppcheck_vulnerable.log" 2>&1
    # The library is analysed together with its callers (secure programs,
    # tests and the secure examples); on its own every public function
    # looks "unused".
    "${CPPCHECK[@]}" src/secure src/lib tests src/examples/*/secure.c > "$LOG/cppcheck_secure.log" 2>&1
    pv=$(grep -c ': \(error\|warning\|style\|performance\|portability\): ' "$LOG/cppcheck_vulnerable.log" || true)
    ps=$(grep -c ': \(error\|warning\|style\|performance\|portability\): ' "$LOG/cppcheck_secure.log" || true)
    sed 's/^/  /' "$LOG/cppcheck_vulnerable.log"
    echo "vulnerable: $pv finding(s)   secure+lib+tests: $ps finding(s)"
    [ "$ps" -eq 0 ] || { SECURE_OK=0; sed 's/^/  SECURE: /' "$LOG/cppcheck_secure.log"; }
    row "cppcheck" "$pv finding(s)" "$ps finding(s)"
else
    echo "cppcheck not installed - skipped"
    row "cppcheck" "skipped" "skipped"
fi

# -----------------------------------------------------------------------------
# 3. Banned / risky string API scan
# -----------------------------------------------------------------------------
banner "3. Banned string API scan (analysis/banned_functions.py)"
python3 analysis/banned_functions.py src/vulnerable > "$LOG/banned_vulnerable.log" 2>&1
python3 analysis/banned_functions.py src/secure src/lib src/examples/*/secure.c > "$LOG/banned_secure.log" 2>&1
bv=$(grep -c '\[' "$LOG/banned_vulnerable.log" || true)
bs=$(grep -c '\[' "$LOG/banned_secure.log" || true)
sed 's/^/  /' "$LOG/banned_vulnerable.log"
echo "vulnerable: $bv finding(s)   secure+lib: $bs finding(s)"
[ "$bs" -eq 0 ] || SECURE_OK=0
row "banned API scan" "$bv finding(s)" "$bs finding(s)"

# -----------------------------------------------------------------------------
# Dynamic test inputs (same inputs for ASan and Valgrind)
#   q1_overflow takes arguments; q2_format reads stdin.
# -----------------------------------------------------------------------------
rep() { printf "%${2}s" "" | tr ' ' "$1"; }
A20="$(rep A 20)"; A100="$(rep A 100)"; U15="abcdefghijklmno"

# name | program | args (space separated, no spaces inside) | stdin
CASES=(
    "q1_normal|q1_overflow|alice cse|"
    "q1_user20_intra_struct|q1_overflow|$A20 cse|"
    "q1_path_overflow|q1_overflow|$U15 $U15|"
    "q1_user100|q1_overflow|$A100 cse|"
    "q2_normal|q2_format||alice\n21\nhello\n"
    "q2_fmt_pointers|q2_format||alice\n21\n%p.%p.%p.%p\n"
    "q2_fmt_strings|q2_format||alice\n21\n%s%s%s%s%s%s%s%s\n"
    "q2_record_overflow|q2_format||alice\n21\n$(rep B 60)\n"
    "q2_name40|q2_format||$(rep A 40)\n21\nhello\n"
)

run_case() {  # run_case BINARY LOGFILE ARGS STDIN [prefix-cmd...]
    local bin="$1" log="$2" args="$3" input="$4"; shift 4
    # shellcheck disable=SC2086
    ( printf '%b' "$input" | timeout 60 "$@" "$bin" $args > "$log" 2>&1; exit $? ) 2>/dev/null
    return $?
}

asan_kind() {
    local k
    k="$(grep -o 'AddressSanitizer: [a-z-]*' "$1" | head -n1 | cut -d' ' -f2)"
    if [ -n "$k" ]; then echo "$k"; return; fi
    grep -q 'runtime error:' "$1" && { echo "UBSan runtime error"; return; }
    if [ "$2" -ge 128 ]; then echo "crash (no report)"; return; fi
    echo "none"
}

# -----------------------------------------------------------------------------
# 4. AddressSanitizer + UBSan
# -----------------------------------------------------------------------------
banner "4. AddressSanitizer + UBSan (bin/asan/*)"
printf '%-24s %-28s %-28s\n' "case" "vulnerable" "secure"
for c in "${CASES[@]}"; do
    IFS='|' read -r name prog args input <<< "$c"
    run_case "bin/asan/vulnerable_$prog" "$LOG/asan_vulnerable_$name.log" "$args" "$input"; rv=$?
    run_case "bin/asan/secure_$prog"     "$LOG/asan_secure_$name.log"     "$args" "$input"; rs=$?
    kv="$(asan_kind "$LOG/asan_vulnerable_$name.log" $rv)"
    ks="$(asan_kind "$LOG/asan_secure_$name.log" $rs)"
    printf '%-24s %-28s %-28s\n' "$name" "$kv" "$ks"
    [ "$ks" = "none" ] || SECURE_OK=0
    row "ASan $name" "$kv" "$ks"
done

# -----------------------------------------------------------------------------
# 5. Valgrind memcheck
# -----------------------------------------------------------------------------
banner "5. Valgrind memcheck (bin/vulnerable/*, bin/secure/*)"
vg_result() {  # vg_result LOGFILE EXITCODE
    local errs leak
    errs="$(grep -o 'ERROR SUMMARY: [0-9]*' "$1" | tail -n1 | awk '{print $3}')"
    leak="$(grep -q 'definitely lost: [1-9]' "$1" && echo ", leak" || true)"
    if grep -q 'Process terminating with default action of signal' "$1"; then
        echo "${errs:-?} err, $(grep -o 'signal [0-9]* ([A-Z]*)' "$1" | head -n1)$leak"
    else
        echo "${errs:-?} errors$leak"
    fi
}
if have valgrind; then
    VG=(valgrind --tool=memcheck --leak-check=full --error-exitcode=99 --track-origins=yes)
    printf '%-24s %-28s %-28s\n' "case" "vulnerable" "secure"
    for c in "${CASES[@]}"; do
        IFS='|' read -r name prog args input <<< "$c"
        run_case "bin/vulnerable/$prog" "$LOG/valgrind_vulnerable_$name.log" "$args" "$input" "${VG[@]}"
        run_case "bin/secure/$prog"     "$LOG/valgrind_secure_$name.log"     "$args" "$input" "${VG[@]}"; rs=$?
        vv="$(vg_result "$LOG/valgrind_vulnerable_$name.log")"
        vs="$(vg_result "$LOG/valgrind_secure_$name.log")"
        printf '%-24s %-28s %-28s\n' "$name" "$vv" "$vs"
        [ "$vs" = "0 errors" ] && [ "$rs" -ne 99 ] || SECURE_OK=0
        row "Valgrind $name" "$vv" "$vs"
    done
else
    echo "valgrind not installed - skipped"
    row "Valgrind" "skipped" "skipped"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
{
    echo
    echo "=========================== ANALYSIS SUMMARY ==========================="
    hr
    printf '| %-30s | %-26s | %-26s |\n' "Check" "Vulnerable version" "Secure version"
    hr
    printf '%s\n' "${SUMMARY[@]}"
    hr
    if [ $SECURE_OK -eq 1 ]; then
        echo "RESULT: secure code is CLEAN in every check."
    else
        echo "RESULT: findings in SECURE code - see analysis/logs/."
    fi
    echo "Logs: analysis/logs/"
} | tee "$LOG/summary.txt"

# Valgrind can still leave vgcore.<pid> files for the expected crashes.
rm -f vgcore.*

[ $SECURE_OK -eq 1 ]
