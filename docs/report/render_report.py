#!/usr/bin/env python3
"""
render_report.py - Copy REAL program output into docs/report/report.md

CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities

report.md contains blocks like

    <!-- BEGIN OUTPUT q1_01_vuln_runs.txt -->
    ...anything...
    <!-- END OUTPUT -->

or, to embed a complete source file,

    <!-- BEGIN CODE src/secure/q1_overflow.c c -->
    <!-- END CODE -->

or, to show only some lines of a long log,

    <!-- BEGIN OUTPUT q1_02_asan_path_overflow.txt lines=1-22 -->

This script replaces everything between the markers with a ```text block
holding the exact contents of docs/report/outputs/<file> (as produced by
collect_outputs.sh). Running it again refreshes the blocks, so the report
can never drift away from the real output.

Usage:  bash docs/report/collect_outputs.sh && python3 docs/report/render_report.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "report.md")
OUTPUTS = os.path.join(HERE, "outputs")

BLOCK = re.compile(
    r"(<!-- BEGIN OUTPUT (?P<file>[\w.\-]+)(?: lines=(?P<a>\d+)-(?P<b>\d+))? -->\n)"
    r".*?"
    r"(?P<end><!-- END OUTPUT -->)",
    re.S,
)


def render(match):
    name = match.group("file")
    path = os.path.join(OUTPUTS, name)
    if not os.path.exists(path):
        sys.exit(f"render_report: missing output file {path} "
                 f"(run collect_outputs.sh first)")
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().rstrip("\n").split("\n")
    note = ""
    if match.group("a"):
        a, b = int(match.group("a")), int(match.group("b"))
        total = len(lines)
        lines = lines[a - 1:b]
        if b < total:
            lines.append(f"... ({total - b} more lines in docs/report/outputs/{name})")
    body = "\n".join(lines)
    note = f"*Real output — `docs/report/outputs/{name}`*\n\n"
    return f"{match.group(1)}{note}```text\n{body}\n```\n{match.group('end')}"


CODE = re.compile(
    r"(<!-- BEGIN CODE (?P<path>[\w./\-]+) (?P<lang>\w+) -->\n)"
    r".*?"
    r"(?P<end><!-- END CODE -->)",
    re.S,
)
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))


def render_code(match):
    path = os.path.join(ROOT, match.group("path"))
    if not os.path.exists(path):
        sys.exit(f"render_report: missing source file {path}")
    with open(path, encoding="utf-8") as fh:
        body = fh.read().rstrip("\n")
    note = f"*Source file — `{match.group('path')}`*\n\n"
    return f"{match.group(1)}{note}```{match.group('lang')}\n{body}\n```\n{match.group('end')}"


def main():
    with open(REPORT, encoding="utf-8") as fh:
        text = fh.read()
    new, count = BLOCK.subn(render, text)
    new, ccount = CODE.subn(render_code, new)
    count += ccount
    with open(REPORT, "w", encoding="utf-8") as fh:
        fh.write(new)
    print(f"render_report: filled {count} output block(s) in {REPORT}")


if __name__ == "__main__":
    main()
