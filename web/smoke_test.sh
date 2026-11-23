#!/usr/bin/env bash
# =============================================================================
#  web/smoke_test.sh - curl checks for every tab of the web app.
#
#  Start the app first (make web   or   python3 web/app.py), then run:
#      bash web/smoke_test.sh            (default http://127.0.0.1:5000)
#      BASE=http://127.0.0.1:5001 bash web/smoke_test.sh
# =============================================================================
set -u
BASE="${BASE:-http://127.0.0.1:5000}"
PASS=0; FAIL=0

# check NAME EXPECTED_REGEX  -- curl args...
check() {
    local name="$1" re="$2"; shift 3
    local out
    out="$(curl -s --max-time 60 "$@")"
    if printf '%s' "$out" | grep -qE -- "$re"; then
        printf 'PASS  %s\n' "$name"; PASS=$((PASS + 1))
    else
        printf 'FAIL  %s\n      expected /%s/, got: %.300s\n' "$name" "$re" "$out"; FAIL=$((FAIL + 1))
    fi
}
# checkp NAME EXPECTED_REGEX PATH JSON  - POST JSON to PATH
checkp() {
    check "$1" "$2" -- -X POST -H "Content-Type: application/json" -d "$4" "$BASE$3"
}

curl -s --max-time 5 -o /dev/null "$BASE/" || { echo "App is not running at $BASE"; exit 1; }

check "page loads"                  'String Vulnerability Lab'       -- "$BASE/"
check "info: tools + sandbox"       '"network_isolated"'             -- "$BASE/api/info"
check "samples available"           '"Mixed string bugs"'            -- "$BASE/api/samples"

# Tab 1 - Code Scanner
checkp "scan: strcpy -> CWE-120"     '"cwe":"CWE-120"'                /api/scan '{"code":"#include <string.h>\nvoid f(char *s){ char b[8]; strcpy(b, s); }"}'
checkp "scan: printf(msg) -> CWE-134" '"cwe":"CWE-134"'               /api/scan '{"code":"#include <stdio.h>\nvoid f(char *m){ printf(m); }"}'
checkp "scan: gets -> critical"      '"severity":"critical"'          /api/scan '{"code":"char *gets(char *);\nint main(void){ char b[8]; gets(b); return 0; }"}'
checkp "scan: safe code scores 100"  '"score":100'                    /api/scan '{"code":"#include <stdio.h>\nint main(void){ char b[8]; snprintf(b, sizeof b, \"%s\", \"hi\"); puts(b); return 0; }"}'
checkp "scan: empty code rejected"   "is empty"                       /api/scan '{"code":""}'

# Tab 2 - Runtime Check
checkp "runtime: stack overflow"     'stack-buffer-overflow'          /api/runtime '{"code":"#include <string.h>\nint main(int c, char **v){ char b[8]; if (c > 1) strcpy(b, v[1]); return b[0]; }","args":"AAAAAAAAAAAAAAAAAAAA"}'
checkp "runtime: use after free"     'heap-use-after-free'            /api/runtime '{"code":"#include <stdlib.h>\nint main(void){ char *p = malloc(4); if (!p) return 1; free(p); return p[0]; }"}'
checkp "runtime: clean program"      '"label":"CLEAN"'                /api/runtime '{"code":"#include <stdio.h>\nint main(void){ char b[16]; if (fgets(b, sizeof b, stdin)) printf(\"%s\", b); return 0; }","stdin":"hello\n"}'
checkp "runtime: compile error"      '"label":"COMPILE ERROR"'        /api/runtime '{"code":"int main(void){ return x; }"}'
checkp "runtime: infinite loop stops" '"label":"TIMEOUT"'             /api/runtime '{"code":"int main(void){ for (;;); }"}'
checkp "runtime: no network"         'NET-BLOCKED'                    /api/runtime '{"code":"#include <stdlib.h>\nint main(void){ return system(\"curl -s -m 3 http://example.com >/dev/null && echo NET-OK || echo NET-BLOCKED\"); }"}'

# Tab 3 - Input Tester
checkp "input: Q1 overflow exploited" '"label":"EXPLOITED"'           /api/input-test '{"name":"AAAAAAAAAAAAAAAAAAAA","role":"cse","age":"21","message":"hi"}'
checkp "input: Q1/Q2 secure rejects"  '"label":"REJECTED"'            /api/input-test '{"name":"AAAAAAAAAAAAAAAAAAAA","role":"cse","age":"21","message":"hi"}'
checkp "input: Q2 secret leaked"      'secret_token leaked'           /api/input-test '{"name":"eve","role":"cse","age":"22","message":"%27$lx"}'
checkp "input: multi-line rejected"   'single lines'                  /api/input-test '{"name":"a\nb","role":"","age":"","message":""}'

# Tab 4 - Examples
check "examples: 20 listed"          'e20_strtok_reentrancy'         -- "$BASE/api/examples"
check "examples: sources"            '"vulnerable":'                 -- "$BASE/api/examples/e01_strcpy_overflow"
checkp "examples: E01-4 passes"       '"pass":true'                   /api/examples/e01_strcpy_overflow/run '{"case":"E01-4"}'
checkp "examples: E13-2 injection"    'command injected'              /api/examples/e13_command_injection/run '{"case":"E13-2"}'
check "examples: unknown example"    'Unknown example'               -- "$BASE/api/examples/e99_nope"

echo
echo "Smoke test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
