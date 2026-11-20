#!/usr/bin/env python3
"""
banned_functions.py - Scan C sources for unsafe string APIs

CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
Module 4 (Vulnerability Detection / Analysis)

Cppcheck does not report most of the classic string APIs (it cannot know how
long argv or stdin data will be), so this small scanner fills the gap, in the
spirit of Microsoft's banned.h. Comments and string literals are blanked out
first (line numbers are preserved), so a comment such as "was: printf(msg)"
in the secure code is not reported.

Usage:   python3 analysis/banned_functions.py FILE_OR_DIR...
Output:  file:line: [RULE] message      (one line per finding)
Exit:    0 if nothing found, 1 if any finding.
"""
import os
import re
import sys

RULES = [
    ("BANNED-gets", re.compile(r"\bgets\s*\("),
     "gets() cannot limit input length (CWE-242)"),
    ("BANNED-strcpy", re.compile(r"\bstrcpy\s*\("),
     "strcpy() does not know the destination size (CWE-120)"),
    ("BANNED-strcat", re.compile(r"\bstrcat\s*\("),
     "strcat() does not know the destination size (CWE-120)"),
    ("BANNED-sprintf", re.compile(r"\b(v?sprintf)\s*\("),
     "sprintf() has no output bound; use snprintf (CWE-787)"),
    ("RISKY-strncpy", re.compile(r"\bstrncpy\s*\("),
     "strncpy() may leave the result unterminated (CWE-170)"),
    ("BANNED-scanf-%s", re.compile(r"\b[sf]?scanf\s*\([^;]*%s"),
     "scanf(\"%s\") without a field width (CWE-120)"),
    ("UNCHECKED-scanf", re.compile(r"^\s*[sf]?scanf\s*\("),
     "scanf() return value is ignored (CWE-252)"),
    ("FORMAT-nonliteral",
     re.compile(r"\b(printf|syslog)\s*\(\s*(?![\"\s])[A-Za-z_][\w\.\->\[\]]*\s*\)"),
     "format string is a variable, not a literal (CWE-134)"),
    ("FORMAT-nonliteral",
     re.compile(r"\bf?printf\s*\(\s*\w+\s*,\s*(?![\"\s])[A-Za-z_][\w\.\->\[\]]*\s*\)"),
     "format string is a variable, not a literal (CWE-134)"),
    ("RISKY-atoi", re.compile(r"\bato[il]l?\s*\("),
     "atoi()/atol() cannot report errors or overflow (CWE-190)"),
]


def blank_comments_and_strings(src):
    """Replace comments and the *contents* of string/char literals with
    spaces, keeping newlines so line numbers stay correct. The quotes of
    string literals are kept so the format-literal rules still work."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            q = c
            j = i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            body = src[i + 1:j]
            # keep '%s' visible inside strings for the scanf rule
            kept = re.sub(r"[^%sdxpn\n]", " ", body) if q == '"' else " " * len(body)
            out.append(q + kept + (q if j < n else ""))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def scan_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        code = blank_comments_and_strings(fh.read())
    findings = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        for rule, rx, msg in RULES:
            if rx.search(line):
                findings.append(f"{path}:{lineno}: [{rule}] {msg}")
    return findings


def main(argv):
    files = []
    for arg in argv[1:]:
        if os.path.isdir(arg):
            for root, _, names in os.walk(arg):
                files += [os.path.join(root, f) for f in sorted(names)
                          if f.endswith((".c", ".h"))]
        else:
            files.append(arg)
    total = []
    for f in sorted(files):
        total += scan_file(f)
    for line in total:
        print(line)
    print(f"banned_functions: {len(total)} finding(s) in {len(files)} file(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
