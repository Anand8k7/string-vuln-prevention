#!/usr/bin/env bash
# =============================================================================
#  run_tests.sh - Run every test suite and print an overall summary
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#  Module 5 (Testing & Evaluation)
#
#  Runs (in order):
#    1. every unit-test binary   bin/tests/test_*
#    2. every scenario script    tests/scenarios/*.sh   (except lib_*.sh)
#  Each suite prints its own PASS/FAIL table and a "TF_RESULT <suite> <p> <t>"
#  line, which is collected here into one summary table.
#
#  Usage: make test        (builds everything first, then calls this script)
# =============================================================================
set -u

cd "$(dirname "$0")/.." || exit 1

declare -a SUITES=() PASSED=() TOTAL=() STATUS=()
overall=0

run_suite() {
    local name="$1"; shift
    local out rc line
    out="$("$@" 2>&1)"
    rc=$?
    printf '%s\n' "$out"
    line="$(printf '%s\n' "$out" | grep '^TF_RESULT ' | tail -n 1)"
    if [ -n "$line" ]; then
        # shellcheck disable=SC2086
        set -- $line
        SUITES+=("$2"); PASSED+=("$3"); TOTAL+=("$4")
    else
        # No result line: the suite crashed (e.g. ASan abort) before reporting.
        SUITES+=("$name"); PASSED+=("0"); TOTAL+=("?")
    fi
    if [ $rc -eq 0 ]; then STATUS+=("PASS"); else STATUS+=("FAIL"); overall=1; fi
}

shopt -s nullglob

for t in bin/tests/test_*; do
    [ -x "$t" ] && run_suite "$(basename "$t")" "$t"
done

for s in tests/scenarios/*.sh; do
    case "$(basename "$s")" in lib_*) continue ;; esac   # helper, not a suite
    run_suite "$(basename "$s" .sh)" bash "$s"
done

if [ ${#SUITES[@]} -eq 0 ]; then
    echo "No test suites found. Run 'make test' to build them first."
    exit 1
fi

echo
echo "=================== OVERALL TEST SUMMARY ==================="
printf '%-28s %8s %8s %8s\n' "Suite" "Passed" "Total" "Result"
printf '%-28s %8s %8s %8s\n' "----------------------------" "------" "-----" "------"
sum_p=0; sum_t=0
for i in "${!SUITES[@]}"; do
    printf '%-28s %8s %8s %8s\n' "${SUITES[$i]}" "${PASSED[$i]}" "${TOTAL[$i]}" "${STATUS[$i]}"
    sum_p=$((sum_p + PASSED[i]))
    [[ "${TOTAL[$i]}" =~ ^[0-9]+$ ]] && sum_t=$((sum_t + TOTAL[i]))
done
printf '%-28s %8s %8s %8s\n' "----------------------------" "------" "-----" "------"
if [ $overall -eq 0 ]; then res="PASS"; else res="FAIL"; fi
printf '%-28s %8d %8d %8s\n' "TOTAL" "$sum_p" "$sum_t" "$res"
echo "============================================================"

exit $overall
