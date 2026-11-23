"""
examples.py - metadata and test cases for the 20 examples in src/examples/.

The test cases are read from tests/scenarios/examples.sh (the same cases
`make test` runs), so the web app and the test suite never disagree.
The case lines are evaluated by bash itself (with ex/t/rep redefined to
print the fields), so quoting is handled exactly as in the test suite.
"""
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX_DIR = os.path.join(ROOT, "src", "examples")
CASES_FILE = os.path.join(ROOT, "tests", "scenarios", "examples.sh")
README = os.path.join(ROOT, "README.md")


# Bash prints each case as fields separated by \x1f, records by \x1e.
# Only the case definitions (lines starting with "ex", "SC_STDIN=", "t ")
# from E01 onwards are evaluated, with ex/t/rep replaced by printers.
_DUMP = r"""
rep() { printf "%${2}s" "" | tr " " "$1"; }
ex()  { printf "EX\x1f%s\x1e" "$1"; }
t()   { printf "T\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s" \
               "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${SC_STDIN-}"
        shift 8; for a in "$@"; do printf "\x1f%s" "$a"; done
        printf "\x1e"; SC_STDIN=""; }
source <(sed -n '/^# -\{5,\}.*E01/,$p' "$1" | grep -E '^(ex |SC_STDIN=|t )')
"""


def load_cases():
    r = subprocess.run(["bash", "-c", _DUMP, "dump", CASES_FILE],
                       capture_output=True, timeout=10, check=True)
    cases, current = {}, None
    for rec in r.stdout.decode("utf-8").split("\x1e"):
        f = rec.split("\x1f")
        if f[0] == "EX":
            current = f[1]
            cases[current] = []
        elif f[0] == "T" and current is not None:
            cid, cat, desc, expect, sec_re, def_re, def_label, stdin = f[1:9]
            cases[current].append({
                "id": cid, "category": cat, "description": desc, "expect": expect,
                "sec_re": sec_re, "def_re": def_re, "def_label": def_label,
                "args": f[9:], "stdin": stdin,
            })
    return cases


def load_table():
    """README table: | # | `eNN_name` | Vulnerability | Fix |"""
    table = {}
    with open(README, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^\|\s*(\d+)\s*\|\s*`(e\d\d_\w+)`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$", line)
            if m:
                table[m.group(2)] = {"number": int(m.group(1)),
                                     "vulnerability": m.group(3), "fix": m.group(4)}
    return table


def _header_field(src, field):
    m = re.search(rf"\*\s+{field}:\s+(.*?)(?=\n \*\s*\n| \*\s+[A-Z][A-Za-z]+:| \*/)", src, re.S)
    if not m:
        return ""
    return re.sub(r"\s*\n\s*\*\s*", " ", m.group(1)).strip()


def list_examples():
    table = load_table()
    cases = load_cases()
    out = []
    for name in sorted(os.listdir(EX_DIR)):
        vpath = os.path.join(EX_DIR, name, "vulnerable.c")
        if not os.path.isfile(vpath):
            continue
        with open(vpath, encoding="utf-8") as f:
            src = f.read()
        meta = table.get(name, {})
        out.append({
            "name": name,
            "number": meta.get("number", int(name[1:3])),
            "vulnerability": meta.get("vulnerability", ""),
            "fix": meta.get("fix", ""),
            "bug": _header_field(src, "Bug"),
            "cwe": _header_field(src, "CWE"),
            "usage": _header_field(src, "Usage"),
            "cases": cases.get(name, []),
        })
    return out


def read_sources(name):
    if not re.fullmatch(r"e\d\d_\w+", name):
        return None
    d = os.path.join(EX_DIR, name)
    try:
        with open(os.path.join(d, "vulnerable.c"), encoding="utf-8") as f:
            v = f.read()
        with open(os.path.join(d, "secure.c"), encoding="utf-8") as f:
            s = f.read()
    except OSError:
        return None
    return {"vulnerable": v, "secure": s}
