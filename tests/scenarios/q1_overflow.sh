#!/usr/bin/env bash
# =============================================================================
#  q1_overflow.sh - Q1 test cases: buffer overflow via strcpy / strcat
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#
#  Program under test:  q1_overflow <username> <department>
#    username: 1..15 chars of [A-Za-z0-9._-]   (buffer username[16])
#    department: 1..15 letters
#    greeting = "Welcome, <username>!"          (buffer greeting[32])
#    path     = "/home/<department>/<username>" (buffer path[32])
#
#  Run with:  make test        or   bash tests/scenarios/q1_overflow.sh
# =============================================================================
PROG=q1_overflow
# shellcheck source=tests/scenarios/lib_scenario.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib_scenario.sh"

# Visible corruption in the output of q1_overflow (no crash):
#   - role is no longer "guest"
#   - greeting line is not "Welcome, <username>!"
sc_defect() {
    local log="$1" role user first
    role="$(grep -m1 '^Role     : ' "$log" | sed 's/^Role     : //')"
    user="$(grep -m1 '^Username : ' "$log" | sed 's/^Username : //')"
    first="$(head -n1 "$log")"
    if grep -q '^Role     : ' "$log"; then
        if [ -z "$role" ]; then echo "role wiped (\"\")"; return; fi
        if [ "$role" != "guest" ]; then echo "role overwritten \"$role\""; return; fi
    fi
    if grep -q '^Username : ' "$log" && [ "$first" != "Welcome, $user!" ]; then
        echo "greeting corrupted"; return
    fi
}

rep() { printf "%${2}s" "" | tr ' ' "$1"; }   # rep CHAR COUNT

sc_init

A15="$(rep A 15)"; A16="$(rep A 16)"; A20="$(rep A 20)"; A24="$(rep A 24)"
A100="$(rep A 100)"; A5000="$(rep A 5000)"
U15="abcdefghijklmno"

#        ID      Category    Input description              Expect
sc_case  Q1-01  Normal      "alice cse"                     ACCEPT -- alice cse
sc_case  Q1-02  Normal      "j.doe-99 ise (allowed ._-)"    ACCEPT -- j.doe-99 ise
sc_case  Q1-03  Boundary    "username 15 chars (max)"       ACCEPT -- "$A15" cse
sc_case  Q1-04  Boundary    "username 16 chars (max+1)"     REJECT -- "$A16" cse
sc_case  Q1-05  Boundary    "path = 31 chars (exact fit)"   ACCEPT -- "$U15" abcdefghi
sc_case  Q1-06  Boundary    "path = 32 chars (1 over)"      REJECT -- "$U15" abcdefghij
sc_case  Q1-07  Boundary    "user 15 + dept 15 (path 37)"   REJECT -- "$U15" "$U15"
sc_case  Q1-08  Invalid     "empty username"                REJECT -- "" cse
sc_case  Q1-09  Invalid     "username \"bob;ls\""           REJECT -- "bob;ls" cse
sc_case  Q1-10  Invalid     "username with space"           REJECT -- "bob smith" cse
sc_case  Q1-11  Invalid     "department \"cse1\" (digit)"   REJECT -- alice cse1
sc_case  Q1-12  Invalid     "missing department argument"   USAGE  -- alice
sc_case  Q1-13  Oversized   "username 20 x 'A'"             REJECT -- "$A20" cse
sc_case  Q1-14  Oversized   "username 24 x 'A'"             REJECT -- "$A24" cse
sc_case  Q1-15  Oversized   "username 100 x 'A'"            REJECT -- "$A100" cse
sc_case  Q1-16  Oversized   "username 5000 x 'A'"           REJECT -- "$A5000" cse
sc_case  Q1-17  Oversized   "department 100 x 'A'"          REJECT -- alice "$A100"

sc_report "q1_overflow"
