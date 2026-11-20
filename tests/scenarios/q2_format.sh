#!/usr/bin/env bash
# =============================================================================
#  q2_format.sh - Q2 test cases: input validation + unsafe formatting
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#
#  Program under test: q2_format   (reads Name, Age, Message from stdin)
#    name:    1..15 chars, letters/space/-.'          (buffer name[16])
#    age:     whole number 1..120
#    message: 1..40 chars, letters/digits/space/.,!?'%-:()/$
#    record = "name=<n> age=<a> msg=<m>"               (buffer record[64])
#
#  The format-string cases only READ memory (%p, %lx, %s); there is no %n.
#  "%27$lx" reads the stack slot that holds the simulated secret_token in
#  this particular build (gcc 13.3, -O0); the slot number is build-specific.
#
#  Run with:  make test        or   bash tests/scenarios/q2_format.sh
# =============================================================================
PROG=q2_format
# shellcheck source=tests/scenarios/lib_scenario.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib_scenario.sh"

SECRET="5ec12e7ab1e"     # value of secret_token in hex, as %lx prints it
CUR_NAME=""; CUR_AGE=""; CUR_MSG=""; CUR_EXP=""

# Visible problems in a vulnerable run that did not crash.
sc_defect() {
    local log="$1" echo_line record
    if grep -qi "$SECRET" "$log"; then
        echo "LEAK: secret_token"; return
    fi
    echo_line="$(grep -m1 '^Your message: ' "$log")"
    if [[ "$CUR_MSG" == *%* ]] && [ "$echo_line" != "Your message: $CUR_MSG" ]; then
        echo "format interpreted"; return
    fi
    record="$(grep -m1 '^Saved record: ' "$log")"
    # record[64] holds at most 63 characters; anything longer was written
    # past the end of the buffer.
    if [ $(( ${#record} - 14 )) -gt 63 ]; then
        echo "record[64] overflowed"; return
    fi
    # Numeric age typed, but a different number was stored (e.g. overflow).
    local got_age
    got_age="$(printf '%s' "$record" | sed -n 's/.* age=\(-\{0,1\}[0-9]*\) msg=.*/\1/p')"
    if [[ "$CUR_AGE" =~ ^-?[0-9]+$ ]] && [ -n "$got_age" ] && [ "$got_age" != "$CUR_AGE" ]; then
        echo "age silently = $got_age"; return
    fi
    if [ "$record" != "Saved record: name=$CUR_NAME age=$CUR_AGE msg=$CUR_MSG" ]; then
        echo "fields mixed up"; return
    fi
    if [ "$CUR_EXP" = "REJECT" ]; then
        echo "invalid input accepted"; return
    fi
}

# An ACCEPTED secure run must echo the message literally and never leak.
sc_secure_check() {
    local log="$1"
    grep -qi "$SECRET" "$log" && return 1
    grep -qxF "Your message: $CUR_MSG" "$log" || return 1
    grep -qxF "Saved record: name=$CUR_NAME age=$CUR_AGE msg=$CUR_MSG" "$log"
}

# q2 ID CATEGORY DESCRIPTION EXPECTED NAME AGE MESSAGE
q2() {
    CUR_NAME="$5"; CUR_AGE="$6"; CUR_MSG="$7"; CUR_EXP="$4"
    SC_STDIN="$(printf '%s\n%s\n%s\n' "$5" "$6" "$7")"$'\n'
    sc_case "$1" "$2" "$3" "$4"
}

rep() { printf "%${2}s" "" | tr ' ' "$1"; }   # rep CHAR COUNT

sc_init

N15="abcdefghijklmno"
M30="$(rep m 30)"; M40="$(rep m 40)"; M41="$(rep m 41)"

#   ID     Category    Description                     Expect  Name          Age    Message
q2 Q2-01  Normal     "alice / 21 / hello"             ACCEPT  alice         21     hello
q2 Q2-02  Normal     "name with space, msg w/ punct"  ACCEPT  "John Smith"  21     "Great course, 10/10!"
q2 Q2-03  Normal     "msg \"50% off!\" (literal %)"   ACCEPT  alice         21     "50% off!"
q2 Q2-04  Boundary   "name 15 chars (max)"            ACCEPT  "$N15"        21     hello
q2 Q2-05  Boundary   "name 16 chars (max+1)"          REJECT  "${N15}p"     21     hello
q2 Q2-06  Boundary   "age 1 (min)"                    ACCEPT  alice         1      hello
q2 Q2-07  Boundary   "age 120 (max)"                  ACCEPT  alice         120    hello
q2 Q2-08  Boundary   "age 0 (min-1)"                  REJECT  alice         0      hello
q2 Q2-09  Boundary   "age 121 (max+1)"                REJECT  alice         121    hello
q2 Q2-10  Boundary   "message 40 chars (max)"         ACCEPT  alice         21     "$M40"
q2 Q2-11  Boundary   "message 41 chars (max+1)"       REJECT  alice         21     "$M41"
q2 Q2-12  Boundary   "record 63 chars (exact fit)"    ACCEPT  "$N15"        120    "$M30"
q2 Q2-13  Boundary   "record 73 chars (too long)"     REJECT  "$N15"        120    "$M40"
q2 Q2-14  Invalid    "age \"abc\" (not a number)"     REJECT  alice         abc    hello
q2 Q2-15  Invalid    "age \"-5\" (negative)"          REJECT  alice         -5     hello
q2 Q2-16  Invalid    "age 20 digits (overflow)"       REJECT  alice         99999999999999999999 hello
q2 Q2-17  Invalid    "name \"bob;ls\""                REJECT  "bob;ls"      21     hello
q2 Q2-18  Invalid    "message \"hi <b>\""             REJECT  alice         21     "hi <b>"
q2 Q2-19  Invalid    "fmt: %p.%p.%p.%p"               ACCEPT  alice         21     "%p.%p.%p.%p"
q2 Q2-20  Invalid    "fmt: %27\$lx (reads secret)"    ACCEPT  alice         21     '%27$lx'
q2 Q2-21  Invalid    "fmt: %s x 8"                    ACCEPT  alice         21     "%s%s%s%s%s%s%s%s"
q2 Q2-22  Oversized  "name 40 chars"                  REJECT  "$(rep A 40)" 21     hello
q2 Q2-23  Oversized  "name 5000 chars"                REJECT  "$(rep A 5000)" 21   hello
q2 Q2-24  Oversized  "message 60 chars"               REJECT  alice         21     "$(rep B 60)"
q2 Q2-25  Oversized  "message 200 chars"              REJECT  alice         21     "$(rep B 200)"

# Missing input (end of file after the age): built by hand.
CUR_NAME="alice"; CUR_AGE="21"; CUR_MSG=""; CUR_EXP="REJECT"
SC_STDIN=$'alice\n21\n'
sc_case Q2-26 Invalid "message missing (EOF)" REJECT

sc_report "q2_format"
