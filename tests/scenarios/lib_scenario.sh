#!/usr/bin/env bash
# =============================================================================
#  lib_scenario.sh - Shared helpers for vulnerable-vs-secure scenario tests
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#  Module 5 (Testing & Evaluation)
#
#  A scenario script sets PROG (program name, e.g. q1_overflow) and calls
#      sc_case ID CATEGORY "input description" EXPECTED -- arg1 arg2 ...
#  (or sets SC_STDIN before calling, to feed text on standard input).
#  Each case is run against four builds:
#      bin/vulnerable/$PROG       (no protections)
#      bin/asan/vulnerable_$PROG  (AddressSanitizer + UBSan)
#      bin/secure/$PROG           (hardened, safe library)
#      bin/asan/secure_$PROG      (secure code under ASan + UBSan)
#  EXPECTED is ACCEPT, REJECT or USAGE and applies to the SECURE version.
#  Optional hooks a scenario script may define:
#      sc_defect LOG        - describe visible corruption in a vulnerable run
#      sc_secure_check LOG  - return non-zero if an ACCEPTED secure run
#                             produced wrong output
#  A case PASSES when the secure build gives the expected result AND the
#  ASan build of the secure code reports no memory error.
#  The vulnerable columns are observations (what actually happened).
#
#  Full output of every run is saved under analysis/logs/scenarios/$PROG/.
# =============================================================================
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

SC_PASS=0
SC_TOTAL=0
SC_STDIN=""
SC_ROWS=()
SC_LOGDIR=""

sc_init() {
    # Binaries under test. Defaults follow the Q1/Q2 layout; a scenario
    # script may set SC_BIN_V / SC_BIN_VA / SC_BIN_S / SC_BIN_SA and
    # SC_LOGNAME before calling sc_init (used by tests/scenarios/examples.sh).
    SC_BIN_V="${SC_BIN_V:-bin/vulnerable/$PROG}"
    SC_BIN_VA="${SC_BIN_VA:-bin/asan/vulnerable_$PROG}"
    SC_BIN_S="${SC_BIN_S:-bin/secure/$PROG}"
    SC_BIN_SA="${SC_BIN_SA:-bin/asan/secure_$PROG}"
    SC_LOGDIR="analysis/logs/scenarios/${SC_LOGNAME:-$PROG}"
    mkdir -p "$SC_LOGDIR"
    rm -f "$SC_LOGDIR"/*.log
    local b
    for b in "$SC_BIN_V" "$SC_BIN_VA" "$SC_BIN_S" "$SC_BIN_SA"; do
        if [ ! -x "$b" ]; then
            echo "Missing $b - run 'make all asan' first." >&2
            exit 1
        fi
    done
}

# Run one binary; output goes to a log file, exit code is returned.
# The input file is passed as stdin (empty file if SC_STDIN is unset).
sc_run() {
    local log="$1"; shift
    local in="$SC_LOGDIR/.stdin"
    printf '%s' "$SC_STDIN" > "$in"
    # Plain ASan defaults: report the first error and exit with code 1.
    # The run happens in a subshell whose stderr is discarded, so bash's own
    # "Segmentation fault" notice for an expected crash does not clutter the
    # table (the crash is still recorded through the exit code).
    (
        ASAN_OPTIONS="detect_leaks=1" UBSAN_OPTIONS="print_stacktrace=1" \
            timeout 10 "$@" < "$in" > "$log" 2>&1
        rc=$?
        exit $rc
    ) 2>/dev/null
    return $?
}

sig_name() { kill -l "$(( $1 - 128 ))" 2>/dev/null || echo "?"; }

# Classify a program run. Program-specific hook `sc_defect LOGFILE` (defined
# by the scenario script) prints a short description of visible corruption,
# or nothing if the output looks normal.
sc_classify_vuln() {
    local log="$1" rc="$2" d
    if [ "$rc" -ge 128 ] && [ "$rc" -ne 255 ]; then
        echo "CRASH (SIG$(sig_name "$rc"))"; return
    fi
    if [ "$rc" -eq 1 ] && grep -q '^Usage:' "$log"; then
        echo "usage error"; return
    fi
    d="$(sc_defect "$log")"
    if [ -n "$d" ]; then echo "$d"; else echo "OK (no visible effect)"; fi
}

sc_classify_asan() {
    local log="$1" rc="$2" kind
    # The SUMMARY line names the error class (e.g. double-free,
    # allocation-size-too-big); fall back to the ERROR line.
    kind="$(grep -o 'SUMMARY: AddressSanitizer: [a-z-]*' "$log" | head -n1 | cut -d' ' -f3)"
    [ -n "$kind" ] || kind="$(grep -o 'AddressSanitizer: [a-z-]*' "$log" | head -n1 | cut -d' ' -f2)"
    if [ -n "$kind" ]; then echo "ASan: $kind"; return; fi
    if grep -q 'LeakSanitizer' "$log"; then echo "LSan: memory leak"; return; fi
    if grep -q 'runtime error:' "$log"; then echo "UBSan: runtime error"; return; fi
    local plain
    plain="$(sc_classify_vuln "$log" "$rc")"
    case "$plain" in
        OK*|usage*) echo "$plain" ;;
        *)          echo "NOT DETECTED: $plain" ;;
    esac
}

sc_classify_secure() {
    local log="$1" rc="$2" reason
    case "$rc" in
        0) echo "ACCEPT" ;;
        1) echo "USAGE" ;;
        2) # Short form of the rejection message for the table.
           reason="$(grep -m1 -o 'REJECTED: .*' "$log" | sed \
               -e 's/^REJECTED: //' -e 's/home directory path/path/' \
               -e 's/ is too long.*/ too long/' -e 's/ would exceed.*/ too long/' \
               -e 's/ contains a character.*/ bad char/' \
               -e 's/ must not be empty/ empty/' -e 's/ is invalid.*/ invalid/' \
               -e 's/ is out of range.*/ out of range/' -e 's/ is not a whole number/ not a number/' \
               -e 's/ is missing.*/ missing/')"
           echo "REJECT: $reason" ;;
        *) if [ "$rc" -ge 128 ]; then echo "CRASH (SIG$(sig_name "$rc"))";
           else echo "ERROR (exit $rc)"; fi ;;
    esac
}

sc_has_sanitizer_error() {
    grep -qE 'AddressSanitizer|LeakSanitizer|runtime error:' "$1"
}

# sc_case ID CATEGORY DESCRIPTION EXPECTED -- ARGS...
sc_case() {
    local id="$1" cat="$2" desc="$3" exp="$4"; shift 4
    [ "${1:-}" = "--" ] && shift
    local lv="$SC_LOGDIR/${id}_vulnerable.log"
    local la="$SC_LOGDIR/${id}_vulnerable_asan.log"
    local ls="$SC_LOGDIR/${id}_secure.log"
    local lsa="$SC_LOGDIR/${id}_secure_asan.log"
    local rv ra rs rsa v a s sa result

    sc_run "$lv"  "$SC_BIN_V"  "$@"; rv=$?
    sc_run "$la"  "$SC_BIN_VA" "$@"; ra=$?
    sc_run "$ls"  "$SC_BIN_S"  "$@"; rs=$?
    sc_run "$lsa" "$SC_BIN_SA" "$@"; rsa=$?

    v="$(sc_classify_vuln "$lv" "$rv")"
    a="$(sc_classify_asan "$la" "$ra")"
    s="$(sc_classify_secure "$ls" "$rs")"
    if sc_has_sanitizer_error "$lsa"; then sa="ERROR"; else sa="clean"; fi

    # Optional program-specific check of an ACCEPTED secure run (e.g. the
    # output must echo the input literally). Defined by the scenario script.
    if [ "$s" = "ACCEPT" ] && declare -F sc_secure_check >/dev/null; then
        if ! sc_secure_check "$ls"; then
            s="ACCEPT but OUTPUT WRONG"
        fi
    fi

    result="FAIL"
    if { [ "$s" = "$exp" ] || [ "${s%%:*}" = "$exp" ]; } &&
       [ "$sa" = "clean" ] && [ "$rs" -eq "$rsa" ]; then
        result="PASS"
        SC_PASS=$((SC_PASS + 1))
    fi
    SC_TOTAL=$((SC_TOTAL + 1))
    SC_ROWS+=("$(printf '| %-5.5s | %-9.9s | %-28.28s | %-24.24s | %-30.30s | %-6.6s | %-28.28s | %-5.5s | %-6s |' \
        "$id" "$cat" "$desc" "$v" "$a" "$exp" "$s" "$sa" "$result")")
    SC_STDIN=""
}

sc_report() {
    local suite="$1"
    local line='+-------+-----------+------------------------------+--------------------------+--------------------------------+--------+------------------------------+-------+--------+'
    echo
    echo "=== Scenario suite: $suite (vulnerable vs secure) ==="
    echo "$line"
    printf '| %-5s | %-9s | %-28s | %-24s | %-30s | %-6s | %-28s | %-5s | %-6s |\n' \
        "ID" "Category" "Input" "Vulnerable (plain)" "Vulnerable (ASan build)" \
        "Expect" "Secure result" "S+ASn" "Result"
    echo "$line"
    printf '%s\n' "${SC_ROWS[@]}"
    echo "$line"
    echo "Summary [$suite]: $SC_PASS/$SC_TOTAL passed, $((SC_TOTAL - SC_PASS)) failed"
    echo "Full program output for every run: $SC_LOGDIR/"
    echo "TF_RESULT $suite $SC_PASS $SC_TOTAL"
    [ "$SC_PASS" -eq "$SC_TOTAL" ]
}
