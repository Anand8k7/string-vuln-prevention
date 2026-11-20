#!/usr/bin/env bash
# =============================================================================
#  examples.sh - Test cases for the 20 small examples in src/examples/
#
#  CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
#
#  Every case is run on four builds of the example (vulnerable, vulnerable +
#  ASan, secure, secure + ASan) through tests/scenarios/lib_scenario.sh.
#  A case PASSES when the secure build gives the expected result (ACCEPT /
#  REJECT), its output matches the expected pattern (for ACCEPT cases), and
#  the secure ASan build reports no error. The vulnerable columns record
#  what actually happened.
#
#  Safety: inputs are local only. The command-injection case injects only a
#  harmless "echo INJECTED"; the path-traversal case reads a test fixture.
#
#  Run with:  make test        or   bash tests/scenarios/examples.sh
#  Negative control:  EX_NEGATIVE_CONTROL=1 bash tests/scenarios/examples.sh
# =============================================================================
PROG=examples
# shellcheck source=tests/scenarios/lib_scenario.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib_scenario.sh"

# Per-case settings (set by t()):
#   SEC_RE     extended regex the SECURE output must match when accepted
#   DEF_RE     regex that reveals a defect in a vulnerable run;
#              prefix "!" = defect when the regex does NOT match
#   DEF_LABEL  text for the table when DEF_RE fires
SEC_RE=""; DEF_RE=""; DEF_LABEL=""; CUR_EXP=""

sc_defect() {
    local log="$1" re
    if [ -n "$DEF_RE" ]; then
        re="${DEF_RE#!}"
        if [ "$re" != "$DEF_RE" ]; then
            grep -qE -- "$re" "$log" || { echo "$DEF_LABEL"; return; }
        else
            grep -qE -- "$re" "$log" && { echo "$DEF_LABEL"; return; }
        fi
    fi
    if [ "$CUR_EXP" = "REJECT" ] && ! grep -qiE 'rejected|error|usage|no input|no such file' "$log"; then
        echo "bad input accepted"
    fi
}

sc_secure_check() {
    [ -z "$SEC_RE" ] && return 0
    grep -qE -- "$SEC_RE" "$1"
}

# ex NAME  - select the four binaries of one example
ex() {
    SC_BIN_V="bin/examples/$1/vulnerable"
    SC_BIN_VA="bin/examples/$1/vulnerable_asan"
    SC_BIN_S="bin/examples/$1/secure"
    SC_BIN_SA="bin/examples/$1/secure_asan"
    # Negative control: test the VULNERABLE builds as if they were secure.
    # The suite must then fail (see docs/report/outputs/ex_02_negative_control.txt).
    if [ "${EX_NEGATIVE_CONTROL:-0}" = 1 ]; then
        SC_BIN_S="$SC_BIN_V"
        SC_BIN_SA="$SC_BIN_VA"
    fi
    SC_LOGNAME="examples/$1"
    sc_init
}

# t ID CATEGORY DESCRIPTION EXPECT SEC_RE DEF_RE DEF_LABEL -- ARGS...
t() {
    local id="$1" cat="$2" desc="$3" exp="$4"
    SEC_RE="$5"; DEF_RE="$6"; DEF_LABEL="$7"; CUR_EXP="$exp"
    shift 7
    [ "${1:-}" = "--" ] && shift
    sc_case "$id" "$cat" "$desc" "$exp" "$@"
}

rep() { printf "%${2}s" "" | tr ' ' "$1"; }   # rep CHAR COUNT

# ---------------------------------------------------------------- E01 strcpy
ex e01_strcpy_overflow
t E01-1 Normal    "alice"                 ACCEPT '^Hello, alice$' '' '' -- alice
t E01-2 Boundary  "15 chars (max)"        ACCEPT '^Hello, A{15}$' '' '' -- "$(rep A 15)"
t E01-3 Boundary  "16 chars (max+1)"      REJECT '' '' '' -- "$(rep A 16)"
t E01-4 Oversized "200 chars"             REJECT '' '' '' -- "$(rep A 200)"

# ---------------------------------------------------------------- E02 strcat
ex e02_strcat_overflow
t E02-1 Normal    "bob"                   ACCEPT '^Hello, bob!$' '' '' -- bob
t E02-2 Boundary  "15 chars (fits 24)"    ACCEPT '^Hello, A{15}!$' '' '' -- "$(rep A 15)"
t E02-3 Boundary  "16 chars (1 over)"     REJECT '' '' '' -- "$(rep A 16)"
t E02-4 Oversized "200 chars"             REJECT '' '' '' -- "$(rep A 200)"

# ---------------------------------------------------------------- E03 format
ex e03_format_string
t E03-1 Normal    "hello world"           ACCEPT '^hello world$' '' '' -- "hello world"
t E03-2 Normal    "50% off"               ACCEPT '^50% off$' '!^50% off$' "format interpreted" -- "50% off"
t E03-3 Invalid   "%p.%p.%p.%p"           ACCEPT '^%p\.%p\.%p\.%p$' '!^%p\.%p\.%p\.%p$' "stack values printed" -- "%p.%p.%p.%p"
t E03-4 Invalid   "%s x 8"                ACCEPT '^(%s){8}$' '!^(%s){8}$' "format interpreted" -- "%s%s%s%s%s%s%s%s"

# ---------------------------------------------------------------- E04 scanf
ex e04_scanf_no_width
SC_STDIN=$'cat\n';            t E04-1 Normal    "word \"cat\""         ACCEPT '^word=cat$' '' '' --
SC_STDIN=$'ABCDEFG\n';        t E04-2 Boundary  "7 chars (max)"        ACCEPT '^word=ABCDEFG$' '' '' --
SC_STDIN=$'ABCDEFGH\n';       t E04-3 Boundary  "8 chars (max+1)"      REJECT '' '' '' --
SC_STDIN="$(rep A 300)"$'\n'; t E04-4 Oversized "300 chars"            REJECT '' '' '' --

# ---------------------------------------------------------------- E05 gets
ex e05_gets
SC_STDIN=$'hello there\n';    t E05-1 Normal    "line \"hello there\"" ACCEPT '^line=hello there$' '' '' --
SC_STDIN="$(rep B 15)"$'\n';  t E05-2 Boundary  "15 chars (max)"       ACCEPT '^line=B{15}$' '' '' --
SC_STDIN="$(rep B 16)"$'\n';  t E05-3 Boundary  "16 chars (max+1)"     REJECT '' '' '' --
SC_STDIN="";                  t E05-4 Invalid   "empty input (EOF)"    REJECT '' '' '' --
SC_STDIN="$(rep B 500)"$'\n'; t E05-5 Oversized "500 chars"            REJECT '' '' '' --

# ---------------------------------------------------------------- E06 off-by-one
ex e06_off_by_one_loop
t E06-1 Normal    "abc"                   ACCEPT '^ABC$' '' '' -- abc
t E06-2 Boundary  "7 chars (max)"         ACCEPT '^ABCDEFG$' '' '' -- abcdefg
t E06-3 Boundary  "8 chars (check passes)" REJECT '' '' '' -- abcdefgh
t E06-4 Oversized "9 chars"               REJECT '' '' '' -- abcdefghi

# ---------------------------------------------------------------- E07 strncpy
ex e07_strncpy_no_terminator
t E07-1 Normal    "tom"                   ACCEPT '^name=tom len=3$' '' '' -- tom
t E07-2 Boundary  "7 chars (max)"         ACCEPT '^name=ABCDEFG len=7$' '' '' -- ABCDEFG
t E07-3 Boundary  "8 chars (no '\\0')"    REJECT '' '' '' -- ABCDEFGH
t E07-4 Oversized "40 chars"              REJECT '' '' '' -- "$(rep C 40)"

# ---------------------------------------------------------------- E08 sprintf
ex e08_sprintf_overflow
t E08-1 Normal    "carol"                 ACCEPT '^user=carol id=42$' '' '' -- carol
t E08-2 Boundary  "20 chars (line 31)"    ACCEPT '^user=D{20} id=42$' '' '' -- "$(rep D 20)"
t E08-3 Boundary  "21 chars (line 32)"    REJECT '' '' '' -- "$(rep D 21)"
t E08-4 Oversized "100 chars"             REJECT '' '' '' -- "$(rep D 100)"

# ---------------------------------------------------------------- E09 length overflow
ex e09_length_integer_overflow
t E09-1 Normal    "abc + def"             ACCEPT '^record of 7 bytes' '' '' -- abc def
t E09-2 Boundary  "200 + 54 (255 bytes)"  ACCEPT '^record of 255 bytes' '' '' -- "$(rep E 200)" "$(rep F 54)"
t E09-3 Boundary  "200 + 55 (256 -> 0)"   REJECT '' '' '' -- "$(rep E 200)" "$(rep F 55)"
t E09-4 Oversized "200 + 100 (301 -> 45)" REJECT '' '' '' -- "$(rep E 200)" "$(rep F 100)"

# ---------------------------------------------------------------- E10 OOB index
ex e10_out_of_bounds_index
t E10-1 Normal    "month 3"               ACCEPT '^Month 3 is March$' '' '' -- 3
t E10-2 Boundary  "month 12"              ACCEPT '^Month 12 is December$' '' '' -- 12
t E10-3 Boundary  "month 13"              REJECT '' '' '' -- 13
t E10-4 Boundary  "month 0"               REJECT '' '' '' -- 0
t E10-5 Invalid   "\"abc\""               REJECT '' '' '' -- abc
t E10-6 Oversized "month 100000"          REJECT '' '' '' -- 100000

# ---------------------------------------------------------------- E11 unterminated
ex e11_unterminated_strlen
SC_STDIN="bob";        t E11-1 Normal    "field \"bob\" (padded)"  ACCEPT '^name=bob len=3$' '' '' --
SC_STDIN="ABCDEFG";    t E11-2 Boundary  "7 chars"                 ACCEPT '^name=ABCDEFG len=7$' '' '' --
SC_STDIN="ABCDEFGH";   t E11-3 Boundary  "8 chars (no '\\0')"      ACCEPT '^name=ABCDEFGH len=8$' '!^name=ABCDEFGH len=8$' "over-read past field" --
SC_STDIN="";           t E11-4 Invalid   "empty record"            REJECT '' '' '' --

# ---------------------------------------------------------------- E12 memcpy size
ex e12_memcpy_wrong_size
t E12-1 Normal    "hi"                    ACCEPT '^copied: hi$' '' '' -- hi
t E12-2 Boundary  "15 chars (max)"        ACCEPT '^copied: G{15}$' '' '' -- "$(rep G 15)"
t E12-3 Boundary  "16 chars (max+1)"      REJECT '' '' '' -- "$(rep G 16)"
t E12-4 Oversized "100 chars"             REJECT '' '' '' -- "$(rep G 100)"

# ---------------------------------------------------------------- E13 command injection
ex e13_command_injection
t E13-1 Normal    "dave"                  ACCEPT '^Hello, dave$' '' '' -- dave
t E13-2 Invalid   "dave; echo INJECTED"   REJECT '' '^INJECTED$' "command injected" -- "dave; echo INJECTED"
t E13-3 Invalid   "dave && echo INJECTED" REJECT '' '^INJECTED$' "command injected" -- "dave && echo INJECTED"
t E13-4 Invalid   "\$(echo INJECTED)"     REJECT '' 'INJECTED' "command injected" -- '$(echo INJECTED)'
t E13-5 Oversized "200 chars"             REJECT '' '' '' -- "$(rep H 200)"

# ---------------------------------------------------------------- E14 path traversal
ex e14_path_traversal
t E14-1 Normal    "welcome.txt"           ACCEPT '^Welcome to the public folder' '' '' -- welcome.txt
t E14-2 Invalid   "../secret.txt"         REJECT '' 'SECRET-TEST-VALUE' "secret file read" -- ../secret.txt
t E14-3 Invalid   "../../examples/secret" REJECT '' 'SECRET-TEST-VALUE' "secret file read" -- ../../examples/secret.txt
t E14-4 Invalid   "missing.txt"           REJECT '' '' '' -- missing.txt
t E14-5 Oversized "300-char name"         REJECT '' '' '' -- "$(rep I 300)"

# ---------------------------------------------------------------- E15 use after free
ex e15_use_after_free
t E15-1 Normal    "erin stay"             ACCEPT '^Goodbye, erin$' '' '' -- erin stay
t E15-2 Normal    "erin logout"           ACCEPT '^Goodbye, erin$' '!^Goodbye, erin$' "freed memory printed" -- erin logout
t E15-3 Invalid   "erin reboot"           REJECT '' '' '' -- erin reboot
t E15-4 Oversized "100-char name logout"  REJECT '' '' '' -- "$(rep J 100)" logout

# ---------------------------------------------------------------- E16 double free
ex e16_double_free
t E16-1 Normal    "frank"                 ACCEPT '^Stored: frank$' '' '' -- frank
t E16-2 Boundary  "31 chars (max)"        ACCEPT '^Stored: K{31}$' '' '' -- "$(rep K 31)"
t E16-3 Boundary  "32 chars (error path)" REJECT '' '' '' -- "$(rep K 32)"
t E16-4 Oversized "1000 chars"            REJECT '' '' '' -- "$(rep K 1000)"

# ---------------------------------------------------------------- E17 unchecked malloc
ex e17_unchecked_malloc
t E17-1 Normal    "64 bytes"              ACCEPT '^allocated: buffer of 64 bytes$' '' '' -- 64
t E17-2 Boundary  "32 bytes (min)"        ACCEPT '^allocated: buffer of 32 bytes$' '' '' -- 32
t E17-3 Boundary  "31 bytes (min-1)"      REJECT '' '' '' -- 31
t E17-4 Invalid   "\"abc\""               REJECT '' '' '' -- abc
t E17-5 Invalid   "-1"                    REJECT '' '' '' -- -1
t E17-6 Oversized "10^15 bytes"           REJECT '' '' '' -- 1000000000000000

# ---------------------------------------------------------------- E18 heap overflow
ex e18_heap_overflow_malloc
t E18-1 Normal    "hello"                 ACCEPT '^HELLO$' '' '' -- hello
t E18-2 Boundary  "1 char"                ACCEPT '^X$' '' '' -- x
t E18-3 Invalid   "empty string"          REJECT '' '' '' -- ""
t E18-4 Oversized "5000 chars"            REJECT '' '' '' -- "$(rep l 5000)"

# ---------------------------------------------------------------- E19 signed/unsigned
ex e19_signed_unsigned_length
t E19-1 Normal    "hello, n=3"            ACCEPT '^prefix="hel"$' '' '' -- hello 3
t E19-2 Boundary  "n=0"                   ACCEPT '^prefix=""$' '' '' -- hello 0
t E19-3 Boundary  "n=31 (max)"            ACCEPT '^prefix="M{31}"$' '' '' -- "$(rep M 40)" 31
t E19-4 Invalid   "n=-1"                  REJECT '' '' '' -- hello -1
t E19-5 Invalid   "n=10 > text length"    REJECT '' '' '' -- abc 10
t E19-6 Oversized "n=99999999999"         REJECT '' '' '' -- hello 99999999999

# ---------------------------------------------------------------- E20 strtok
ex e20_strtok_reentrancy
t E20-1 Normal    "a=1,b=2,c=3"           ACCEPT '^c = 3$' '!^c = 3$' "pairs lost" -- "a=1,b=2,c=3"
t E20-2 Boundary  "a=1 (one pair)"        ACCEPT '^a = 1$' '' '' -- "a=1"
t E20-3 Invalid   "a=1,b (no value)"      REJECT '' '' '' -- "a=1,b"
t E20-4 Invalid   "a=1;rm (bad char)"     REJECT '' '' '' -- "a=1;rm"
t E20-5 Oversized "200 chars"             REJECT '' '' '' -- "$(rep k 199)=1"

SC_LOGDIR="analysis/logs/scenarios/examples"
sc_report "examples"
