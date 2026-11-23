#!/usr/bin/env bash
# =============================================================================
#  demo.sh - step-by-step demo of Q1 (q1_overflow) and Q2 (q2_format),
#            vulnerable vs secure, with AddressSanitizer and cppcheck.
#
#  Usage:  ./demo.sh             interactive, pauses between steps
#          ./demo.sh --no-pause  run every step without pausing
# =============================================================================
set -u
cd "$(dirname "$0")"

PAUSE=1
[ "${1:-}" = "--no-pause" ] && PAUSE=0

if [ -t 1 ]; then
    BOLD=$'\e[1m'; CYAN=$'\e[36m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
    BOLD=""; CYAN=""; DIM=""; RESET=""
fi

STEP=0
heading() {
    STEP=$((STEP + 1))
    echo
    echo "${BOLD}${CYAN}=== Step $STEP: $1 ===${RESET}"
}

# Print a command, then run it through bash so pipes work.
run() {
    echo "${DIM}\$ $1${RESET}"
    bash -o pipefail -c "$1"
    echo "${DIM}[exit status: $?]${RESET}"
}

pause() {
    [ "$PAUSE" -eq 1 ] || return 0
    echo
    printf 'Press Enter to continue...'
    read -r _ || true
}

# Leak checking is off so only the overflow report is shown.
export ASAN_OPTIONS="detect_leaks=0"

# -----------------------------------------------------------------------------
heading "Build the programs"
BINS="bin/vulnerable/q1_overflow bin/secure/q1_overflow
      bin/asan/vulnerable_q1_overflow bin/asan/secure_q1_overflow
      bin/vulnerable/q2_format bin/secure/q2_format
      bin/asan/vulnerable_q2_format bin/asan/secure_q2_format"
missing=0
for b in $BINS; do [ -x "$b" ] || missing=1; done
if [ "$missing" -eq 1 ]; then
    echo "Some programs are missing, building them:"
    run "make all asan" || true
    for b in $BINS; do
        [ -x "$b" ] || { echo "ERROR: $b was not built"; exit 1; }
    done
else
    echo "All programs are already built."
fi
pause

# -----------------------------------------------------------------------------
heading "Q1 vulnerable: normal input"
run "./bin/vulnerable/q1_overflow alice cse"
pause

heading "Q1 vulnerable: 20-character username overwrites the role"
run "./bin/vulnerable/q1_overflow AAAAAAAAAAAAAAAAAAAA cse"
pause

heading "Q1 vulnerable under AddressSanitizer"
run "./bin/asan/vulnerable_q1_overflow abcdefghijklmno abcdefghijklmno"
pause

heading "Q1 secure: the same long username is rejected"
run "./bin/secure/q1_overflow alice cse"
run "./bin/secure/q1_overflow AAAAAAAAAAAAAAAAAAAA cse"
pause

heading "Q1 secure under AddressSanitizer: no errors"
run "./bin/asan/secure_q1_overflow abcdefghijklmno abcdefghijklmno"
pause

# -----------------------------------------------------------------------------
heading "Q2 vulnerable: normal input"
run "printf 'alice\n21\nhello\n' | ./bin/vulnerable/q2_format"
pause

heading "Q2 vulnerable: format string in the message - printf(msg)"
run "printf 'alice\n21\n%%p.%%p.%%p.%%p\n' | ./bin/vulnerable/q2_format"
pause

heading "Q2 vulnerable: unchecked scanf(\"%d\") - fields shift"
run "printf 'alice\nabc\nhello\n' | ./bin/vulnerable/q2_format"
pause

heading "Q2 vulnerable under AddressSanitizer: sprintf overflows record[64]"
run "printf 'alice\n21\n%s\n' \$(printf 'B%.0s' {1..60}) | ./bin/asan/vulnerable_q2_format"
pause

heading "Q2 secure: message printed literally, bad age rejected"
run "printf 'alice\n21\n%%p.%%p.%%p.%%p\n' | ./bin/secure/q2_format"
run "printf 'alice\nabc\nhello\n' | ./bin/secure/q2_format"
pause

heading "Q2 secure under AddressSanitizer: long message rejected, no errors"
run "printf 'alice\n21\n%s\n' \$(printf 'B%.0s' {1..60}) | ./bin/asan/secure_q2_format"
pause

# -----------------------------------------------------------------------------
CPPCHECK="cppcheck --enable=warning,style,performance,portability --std=c11 \
--inline-suppr --suppress=missingIncludeSystem -Isrc/lib \
--template='{file}:{line}: {severity}: {message} [{id}]' -q"

heading "cppcheck on the vulnerable Q1 and Q2 sources"
if command -v cppcheck >/dev/null 2>&1; then
    run "$CPPCHECK src/vulnerable/q1_overflow.c src/vulnerable/q2_format.c"
else
    echo "cppcheck is not installed (sudo apt-get install cppcheck) - skipped"
fi
pause

heading "cppcheck on the secure Q1 and Q2 sources and the library"
if command -v cppcheck >/dev/null 2>&1; then
    cmd="$CPPCHECK src/secure/q1_overflow.c src/secure/q2_format.c src/lib/*.c"
    echo "${DIM}\$ $cmd${RESET}"
    out=$(bash -c "$cmd" 2>&1)
    if [ -n "$out" ]; then echo "$out"; else echo "No findings."; fi
else
    echo "cppcheck is not installed (sudo apt-get install cppcheck) - skipped"
fi

echo
echo "${BOLD}Demo finished.${RESET}"
