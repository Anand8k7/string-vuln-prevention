#!/usr/bin/env python3
"""
build_final_report.py - Fill the college template and produce
docs/report/Final_Project_Report.docx and Final_Project_Report.pdf

CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities

* Opens docs/report/SecureCoding-Project Report-Template.docx and keeps its
  page setup, header (logo), footer (page number), fonts and styles.
* Fills the title page and the certificate in place.
* Inserts the Abstract before the template's "Contents" page and replaces the
  template's guidance note with sections 3-18 and two appendices.
* Every number and every terminal output comes from files written by real
  runs: docs/report/outputs/*.txt (collect_outputs.sh), the source code,
  screenshots/*.png (captured by the team) and docs/report/figures/*.png
  (make_figures.py: diagrams + captured terminal output).
* Page numbers in the Contents table and the List of Figures/Tables are
  taken from the rendered PDF (LibreOffice) in a second pass.

Usage (from the repository root):
    python3 docs/report/make_figures.py
    python3 docs/report/build_final_report.py
"""
import copy
import glob
import os
import re
import shutil
import subprocess
import sys

import docx
from docx.text.paragraph import Paragraph
from docx.enum.section import WD_SECTION
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
TEMPLATE = os.path.join(HERE, "SecureCoding-Project Report-Template.docx")
OUT_DOCX = os.path.join(HERE, "Final_Project_Report.docx")
OUT_PDF = os.path.join(HERE, "Final_Project_Report.pdf")
OUTPUTS = os.path.join(HERE, "outputs")
SHOTS = os.path.join(ROOT, "screenshots")
FIGS = os.path.join(HERE, "figures")

TITLE = "Implementing Prevention Methods for String Vulnerabilities"
TEAM = [("Yuval", "1MS24CY021"), ("Anand", "1MS24CY010"), ("Sathish Kumar S", "1MS24CY055")]
MONO = "Courier New"
SERIF = "Times New Roman"
FIG_WIDTH_CM = 15.0
TEXT_WIDTH_CM = 16.2


# =============================================================================
# Real data
# =============================================================================
def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def out(name):
    return read(os.path.join(OUTPUTS, name))


def strip_cmd(text):
    """Drop the '$ command' line and '[exit code: N]' trailer of a single run."""
    lines = [l for l in text.rstrip("\n").split("\n")]
    if lines and lines[0].startswith("$ "):
        lines = lines[1:]
    lines = [l for l in lines if not l.startswith("[exit code:")]
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def table_rows(text, first_col_re):
    rows = []
    for line in text.split("\n"):
        if re.match(r"\|\s*" + first_col_re, line):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows


def tidy_rows(rows):
    """The test script cuts the secure-result column at 44 characters; end such
    labels at a word boundary with an ellipsis instead of mid-word."""
    for r in rows:
        if len(r) > 6 and len(r[6]) >= 44:
            r[6] = r[6][:44].rsplit(" ", 1)[0] + " \u2026"
    return rows


UNIT_SS = table_rows(out("02_unit_safe_string.txt"), r"[A-Z]{2}-\d")
UNIT_IH = table_rows(out("03_unit_input_handler.txt"), r"[A-Z]{2}-\d")
Q1 = tidy_rows(table_rows(out("q1_07_tests.txt"), r"Q1-\d"))
Q2 = tidy_rows(table_rows(out("q2_06_tests.txt"), r"Q2-\d"))
EX = tidy_rows(table_rows(out("ex_01_tests.txt"), r"E\d\d-\d"))


def summary_of(text, suite):
    m = re.search(r"Summary \[" + suite + r"\]: (\d+)/(\d+) passed", text)
    return int(m.group(1)), int(m.group(2))


TOTALS = {
    "safe_string": summary_of(out("02_unit_safe_string.txt"), "safe_string"),
    "input_handler": summary_of(out("03_unit_input_handler.txt"), "input_handler"),
    "q1_overflow": summary_of(out("q1_07_tests.txt"), "q1_overflow"),
    "q2_format": summary_of(out("q2_06_tests.txt"), "q2_format"),
    "examples": summary_of(out("ex_01_tests.txt"), "examples"),
}
m = re.search(r"TOTAL\s+(\d+)\s+(\d+)\s+(\w+)", out("90_make_test_summary.txt"))
GRAND_PASS, GRAND_TOTAL, GRAND_RESULT = int(m.group(1)), int(m.group(2)), m.group(3)
assert GRAND_PASS == sum(p for p, _ in TOTALS.values()) and GRAND_RESULT == "PASS"
NEG = {
    "q1_overflow": summary_of(out("q1_09_negative_control.txt"), "q1_overflow"),
    "q2_format": summary_of(out("q2_07_negative_control.txt"), "q2_format"),
    "examples": summary_of(out("ex_02_negative_control.txt"), "examples"),
}

ENV = {}
for blk in out("00_environment.txt").split("\n\n"):
    ls = blk.strip().split("\n")
    if len(ls) >= 2:
        ENV[ls[0][2:]] = ls[1]
GCC = ENV["gcc --version | head -n1"]
CPPCHECK = ENV["cppcheck --version"]
VALGRIND = ENV["valgrind --version"]
MAKE = ENV["make --version | head -n1"]
KERNEL = ENV["uname -sr"]

ANALYSIS = out("91_analysis.txt")
ANALYSIS_ROWS = []
for line in ANALYSIS.split("\n"):
    mm = re.match(r"\|\s*(gcc warnings|cppcheck|banned API scan|ASan \S+|Valgrind \S+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|", line)
    if mm:
        ANALYSIS_ROWS.append([mm.group(1), mm.group(2), mm.group(3)])
assert "RESULT: secure code is CLEAN in every check." in ANALYSIS


def defect_q(rows):
    """Q1/Q2: the vulnerable programs never reject input, so a case shows a
    defect when either vulnerable column is not OK, or when the input should
    be rejected but the vulnerable build accepted it."""
    n = 0
    for r in rows:
        v, a, exp = r[3], r[4], r[5]
        bad = lambda s: not (s.startswith("OK") or s.startswith("usage"))
        if bad(v) or bad(a) or (exp == "REJECT" and v.startswith("OK")):
            n += 1
    return n


def asan_hits(rows):
    return sum(1 for r in rows if r[4].startswith(("ASan", "UBSan")))


EX_DEFECT = sum(1 for r in EX if not (r[3].startswith("OK") and r[4].startswith("OK")))
EX_ASAN = asan_hits(EX)
EX_BY_CAT = {}
for r in EX:
    c = EX_BY_CAT.setdefault(r[1], [0, 0, 0, 0])
    c[0] += 1
    c[1] += 0 if (r[3].startswith("OK") and r[4].startswith("OK")) else 1
    c[2] += 1 if r[4].startswith(("ASan", "UBSan")) else 0
    c[3] += 1 if r[8] == "PASS" else 0


def loc(path):
    return sum(1 for _ in open(os.path.join(ROOT, path), encoding="utf-8"))


EXAMPLES = [
    ("e01_strcpy_overflow", "strcpy overflow", "CWE-120, 121", "strcpy into name[16]", "safe_copy, reject on SS_TRUNCATED"),
    ("e02_strcat_overflow", "strcat overflow", "CWE-120, 121", "strcat into msg[24]", "safe_concat on total size"),
    ("e03_format_string", "Format string", "CWE-134", "printf(argv[1])", "printf(\"%s\\n\", argv[1])"),
    ("e04_scanf_no_width", "scanf(\"%s\") without width", "CWE-120, 242", "scanf(\"%s\", word[8])", "scanf(\"%7s\") + next-char check"),
    ("e05_gets", "gets()", "CWE-242, 120", "gets(line[16])", "input_read_line (bounded fgets)"),
    ("e06_off_by_one_loop", "Off-by-one in a loop", "CWE-193, 787", "len > size; i <= len", "len >= size; i < len; explicit '\\0'"),
    ("e07_strncpy_no_terminator", "Missing '\\0' after strncpy", "CWE-170, 126", "strncpy(name, s, sizeof name)", "safe_copy (always terminates)"),
    ("e08_sprintf_overflow", "sprintf -> snprintf", "CWE-120, 787", "sprintf(line[32], ...)", "snprintf + return-value check"),
    ("e09_length_integer_overflow", "Integer overflow in length", "CWE-190, 122, 131", "unsigned char total wraps", "size_t, wrap check, limit before narrowing"),
    ("e10_out_of_bounds_index", "Out-of-bounds index", "CWE-129, 125", "months[atoi(s) - 1]", "validate_integer(s, 1, 12)"),
    ("e11_unterminated_strlen", "strlen on unterminated data", "CWE-170, 126", "strlen/%s on full 8-byte field", "safe_strlen + printf(\"%.*s\")"),
    ("e12_memcpy_wrong_size", "memcpy with wrong size", "CWE-805, 787", "memcpy(dst, src, sizeof src)", "size from data, checked vs dst"),
    ("e13_command_injection", "Command injection (system)", "CWE-78", "system(\"echo Hello, \" + name)", "no shell + whitelist"),
    ("e14_path_traversal", "Path traversal", "CWE-22", "BASE_DIR + name, unchecked", "whitelist + realpath containment"),
    ("e15_use_after_free", "Use-after-free", "CWE-416", "printf after free on logout", "use, free once, set NULL"),
    ("e16_double_free", "Double free", "CWE-415", "free in error path and at end", "single clean-up point"),
    ("e17_unchecked_malloc", "Unchecked malloc result", "CWE-252, 690, 789", "malloc(n) result not checked", "range check + NULL check"),
    ("e18_heap_overflow_malloc", "Heap overflow (malloc(strlen))", "CWE-122, 131, 193", "malloc(strlen(s)) + strcpy", "malloc(len + 1) + safe_copy"),
    ("e19_signed_unsigned_length", "Signed/unsigned length", "CWE-195, 839", "int n, upper bound only", "both bounds, size_t, n <= strlen"),
    ("e20_strtok_reentrancy", "strtok vs strtok_r", "CWE-663", "nested strtok calls", "strtok_r + key=value validation"),
]


def example_observed(idx):
    """Distinct observations for one example, from the real test table."""
    pid = f"E{idx:02d}-"
    rows = [r for r in EX if r[0].startswith(pid)]
    vul, asn = [], []
    for r in rows:
        for lab, lst in ((r[3], vul), (r[4], asn)):
            if not lab.startswith("OK") and lab not in lst:
                lst.append(lab)
    passed = sum(1 for r in rows if r[8] == "PASS")
    return rows, vul, asn, passed


# =============================================================================
# Document helpers
# =============================================================================
class Report:
    def __init__(self, pages):
        self.d = docx.Document(TEMPLATE)
        self.pages = pages or {}
        self.figures = []      # (label, caption)
        self.tables = []
        self._styles()

    # ---------------------------------------------------------------- styles
    def _styles(self):
        st = self.d.styles
        black = RGBColor(0, 0, 0)

        def font(style, size, bold=None, italic=None, name=SERIF):
            style.font.name = name
            rpr = style.element.get_or_add_rPr()
            rf = rpr.find(qn("w:rFonts"))
            for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
                rf.set(qn(a), name)
            for a in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
                if rf.get(qn(a)) is not None:
                    del rf.attrib[qn(a)]
            style.font.size = Pt(size)
            if bold is not None:
                style.font.bold = bold
            if italic is not None:
                style.font.italic = italic

        body = st.add_style("Report Body", WD_STYLE_TYPE.PARAGRAPH)
        body.base_style = st["Normal"]
        font(body, 12)
        pf = body.paragraph_format
        pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        pf.space_before = Pt(0)
        pf.space_after = Pt(6)
        pf.line_spacing = 1.5

        for name, size, before, after in (("Heading 1", 16, 0, 18), ("Heading 2", 14, 12, 6),
                                          ("Heading 3", 12, 10, 4)):
            h = st[name]
            font(h, size, bold=True, italic=False)
            h.font.underline = False
            h.font.color.rgb = black
            h.paragraph_format.space_before = Pt(before)
            h.paragraph_format.space_after = Pt(after)
            h.paragraph_format.keep_with_next = True
            h.paragraph_format.line_spacing = 1.15
        st["Heading 1"].paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
        st["Heading 2"].paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
        st["Heading 3"].paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT

        cap = st.add_style("Caption", WD_STYLE_TYPE.PARAGRAPH)
        cap.base_style = st["Normal"]
        font(cap, 10.5, bold=False, italic=True)
        cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.space_before = Pt(4)
        cap.paragraph_format.space_after = Pt(12)
        cap.paragraph_format.line_spacing = 1.0

        code = st.add_style("Code", WD_STYLE_TYPE.PARAGRAPH)
        code.base_style = st["Normal"]
        font(code, 9.5, name=MONO)
        cpf = code.paragraph_format
        cpf.space_after = Pt(0)
        cpf.space_before = Pt(0)
        cpf.line_spacing = 1.0
        cpf.left_indent = Cm(0.15)
        cpf.right_indent = Cm(0.15)
        cpf.alignment = WD_ALIGN_PARAGRAPH.LEFT
        ppr = code.element.get_or_add_pPr()
        bdr = OxmlElement("w:pBdr")          # one grey box around consecutive code lines
        for side in ("top", "left", "bottom", "right"):
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), "4")
            e.set(qn("w:space"), "4")
            e.set(qn("w:color"), "A6A6A6")
            bdr.append(e)
        ppr.append(bdr)
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), "F2F2F2")
        ppr.append(shd)

        tt = st.add_style("Table Text", WD_STYLE_TYPE.PARAGRAPH)
        tt.base_style = st["Normal"]
        font(tt, 10.5)
        tt.paragraph_format.space_after = Pt(0)
        tt.paragraph_format.space_before = Pt(0)
        tt.paragraph_format.line_spacing = 1.0
        tt.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT

        lst = st.add_style("List Item", WD_STYLE_TYPE.PARAGRAPH)
        lst.base_style = body

        # footer page number: Calibri (not installable here) -> Times New Roman
        for sec in self.d.sections:
            for part in (sec.footer, sec.first_page_footer):
                for rf in part._element.iter(qn("w:rFonts")):
                    for a in ("w:ascii", "w:hAnsi", "w:cs"):
                        rf.set(qn(a), SERIF)

    # ---------------------------------------------------------------- text
    def _runs(self, p, text, size=None, mono_size=None, plain=False):
        """**bold** and `code` inline markup (plain=True: code shown in the body font)."""
        for part in re.split(r"(\*\*.+?\*\*|`[^`]+`)", text):
            if not part:
                continue
            if part.startswith("**") and part.endswith("**"):
                r = p.add_run(part[2:-2])
                r.bold = True
            elif part.startswith("`") and part.endswith("`"):
                r = p.add_run(part[1:-1])
                if not plain:
                    r.font.name = MONO
                    r.font.size = Pt(mono_size or 11)
            else:
                r = p.add_run(part)
            if size and (plain or not part.startswith("`")):
                r.font.size = Pt(size)
        return p

    def h1(self, text):
        p = self.d.add_paragraph(style="Heading 1")
        p.paragraph_format.page_break_before = True
        p.add_run(text)
        return p

    def h2(self, text):
        p = self.d.add_paragraph(style="Heading 2")
        p.add_run(text)
        return p

    def h3(self, text):
        p = self.d.add_paragraph(style="Heading 3")
        p.add_run(text)
        return p

    def para(self, text, style="Report Body"):
        p = self.d.add_paragraph(style=style)
        return self._runs(p, text)

    def bullets(self, items, numbered=False):
        for i, t in enumerate(items, 1):
            p = self.d.add_paragraph(style="Report Body")
            pf = p.paragraph_format
            pf.left_indent = Cm(0.9)
            pf.first_line_indent = Cm(-0.6)
            pf.space_after = Pt(3)
            pf.tab_stops.add_tab_stop(Cm(0.9))
            p.add_run(f"{i}.\t" if numbered else "•\t")
            self._runs(p, t)

    def code(self, lines, **_ignored):
        """Code block: Courier New 9.5 pt, single spacing, one grey bordered box
        (the border and shading come from the Code style)."""
        while lines and not lines[-1].strip():
            lines = lines[:-1]
        for i, line in enumerate(lines):
            p = self.d.add_paragraph(style="Code")
            p.add_run(line.replace("\t", "    ") if line else " ")
            if i < len(lines) - 1 and len(lines) <= 45:
                p.paragraph_format.keep_with_next = True    # short blocks stay on one page
        gap = self.d.add_paragraph(style="Report Body")
        gap.paragraph_format.space_after = Pt(0)
        gap.paragraph_format.line_spacing = 1.0

    @staticmethod
    def _shade_par(p, fill):
        pPr = p._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), fill)
        pPr.append(shd)

    # ---------------------------------------------------------------- captions
    def caption(self, kind, label, text):
        p = self.d.add_paragraph(style="Caption")
        r = p.add_run(f"{kind} {label}: ")
        r.bold = True
        p.add_run(text)
        (self.figures if kind == "Figure" else self.tables).append((label, text))
        return p

    def figure(self, path, label, caption, max_h_cm=20.0, **_ignored):
        """All figures are centred and FIG_WIDTH_CM wide; very tall images are
        limited by height instead so that they never exceed the page."""
        from PIL import Image
        with Image.open(path) as im:
            w, h = im.size
        width = FIG_WIDTH_CM
        if width * h / w > max_h_cm:
            width = max_h_cm * w / h
        p = self.d.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.keep_with_next = True
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(0)
        p.add_run().add_picture(path, width=Cm(width))
        self.caption("Figure", label, caption)

    def shot(self, fname, label, caption, **kw):
        path = os.path.join(SHOTS, fname)
        assert os.path.exists(path), path
        self.figure(path, label, caption, **kw)

    # ---------------------------------------------------------------- tables
    def table(self, label, caption, header, rows, widths, size=10.5, mono_cols=()):
        size = 10.5                      # one table font size everywhere
        scale = TEXT_WIDTH_CM / sum(widths)
        widths = [w * scale for w in widths]   # fit the page width exactly
        cp = self.caption("Table", label, caption)
        cp.paragraph_format.keep_with_next = True
        cp.paragraph_format.space_before = Pt(8)
        cp.paragraph_format.space_after = Pt(4)
        t = self.d.add_table(rows=1, cols=len(header))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        self._borders(t)
        self._fixed_widths(t, widths)
        for i, htxt in enumerate(header):
            c = t.rows[0].cells[i]
            self._cell(c, htxt, size, bold=True, fill="D9E2F3", width=widths[i])
        trPr = t.rows[0]._tr.get_or_add_trPr()
        th = OxmlElement("w:tblHeader")
        th.set(qn("w:val"), "true")
        trPr.append(th)
        for row in rows:
            cells = t.add_row().cells
            for i, val in enumerate(row):
                self._cell(cells[i], str(val), size, width=widths[i])
        for r in t.rows:                   # a row never breaks across pages
            trPr = r._tr.get_or_add_trPr()
            cs = OxmlElement("w:cantSplit")
            cs.set(qn("w:val"), "true")
            trPr.append(cs)
        if len(rows) <= 22:                # keep short tables in one piece
            for r in t.rows[:-1]:
                for c in r.cells:
                    for p in c.paragraphs:
                        p.paragraph_format.keep_with_next = True
        sp = self.d.add_paragraph(style="Report Body")
        sp.paragraph_format.space_after = Pt(4)
        return t

    def _cell(self, cell, text, size, bold=False, fill=None, width=None, mono=False):
        cell.width = Cm(width)
        p = cell.paragraphs[0]
        p.style = self.d.styles["Table Text"]
        self._runs(p, text, size=size, plain=True)
        if bold:
            for r in p.runs:
                r.bold = True
        if fill:
            tcPr = cell._tc.get_or_add_tcPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), fill)
            tcPr.append(shd)

    @staticmethod
    def _fixed_widths(t, widths):
        """Fixed layout + explicit grid, so Word and LibreOffice use our widths."""
        tblPr = t._tbl.tblPr
        lay = tblPr.find(qn("w:tblLayout"))     # python-docx adds one for autofit=False
        if lay is None:
            lay = OxmlElement("w:tblLayout")
            tblPr.append(lay)
        lay.set(qn("w:type"), "fixed")
        tw = tblPr.find(qn("w:tblW"))
        if tw is None:
            tw = OxmlElement("w:tblW")
            tblPr.append(tw)
        tw.set(qn("w:w"), str(int(sum(widths) * 567)))
        tw.set(qn("w:type"), "dxa")
        for col, w in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths):
            col.set(qn("w:w"), str(int(w * 567)))

    @staticmethod
    def _borders(t):
        tblPr = t._tbl.tblPr
        b = OxmlElement("w:tblBorders")
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), "4")
            e.set(qn("w:space"), "0")
            e.set(qn("w:color"), "808080")
            b.append(e)
        tblPr.append(b)
        mar = OxmlElement("w:tblCellMar")
        for side, v in (("top", 25), ("left", 70), ("bottom", 25), ("right", 70)):   # schema order
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:w"), str(v))
            e.set(qn("w:type"), "dxa")
            mar.append(e)
        tblPr.append(mar)

    def page(self, key):
        return str(self.pages.get(key, "--"))


# =============================================================================
# Template parts: title page, certificate, contents
# =============================================================================
def set_runs(p, text):
    p.runs[0].text = text
    for r in p.runs[1:]:
        r._r.getparent().remove(r._r)


def fill_front_matter(rep):
    d = rep.d
    P = d.paragraphs
    # Title page -----------------------------------------------------------
    t = next(p for p in P if p.text.strip() == "<Title of the project>")
    set_runs(t, TITLE)
    sem = next(p for p in P if "academic requirements of 7" in p.text)
    for r in sem.runs:
        if r.text.endswith("requirements of 7"):
            r.text = r.text[:-1] + "5"          # 7th -> 5th semester
    names = [p for p in P if p.text.strip() == "Name USN"]
    assert len(names) == 2
    set_runs(names[0], f"{TEAM[0][0]} {TEAM[0][1]}")
    set_runs(names[1], f"{TEAM[1][0]} {TEAM[1][1]}")
    third = copy.deepcopy(names[1]._p)
    names[1]._p.addnext(third)
    third_p = Paragraph(third, names[1]._parent)
    set_runs(third_p, f"{TEAM[2][0]} {TEAM[2][1]}")
    # one empty line less after the names, so the title page stays one page
    nxt = third.getnext()
    if nxt is not None and nxt.tag == qn("w:p") and not "".join(nxt.itertext()).strip():
        nxt.getparent().remove(nxt)

    # Certificate ----------------------------------------------------------
    cert = next(p for p in P if "This is to certify" in p.text)
    r0 = cert.runs[0]
    who = (f"{TEAM[0][0]} ({TEAM[0][1]}), {TEAM[1][0]} ({TEAM[1][1]}) and "
           f"{TEAM[2][0]} ({TEAM[2][1]})")
    r0.text = (r0.text.replace("“<Title>”", "“" + TITLE + "”")
               .replace("<Name> (<USN>) and <Name> (<USN>)", who))
    assert "<" not in cert.text, cert.text

    # Remove the empty lines between "Student Sign" and "Contents"; the
    # Abstract (inserted there) starts on a new page anyway.
    body = d.element.body
    sign = next(p for p in P if p.text.startswith("Student"))
    contents = next(p for p in P if p.text.strip() == "Contents")
    el = sign._p.getnext()
    removed = 0
    while el is not None and el is not contents._p:
        nxt = el.getnext()
        if el.tag == qn("w:p") and not "".join(el.itertext()).strip() and removed < 40:
            if el.find(".//" + qn("w:sectPr")) is None:
                body.remove(el)
                removed += 1
        el = nxt
    contents.style = d.styles["Heading 1"]
    set_runs(contents, "2. Table of Contents")
    contents.paragraph_format.page_break_before = True

    # Remove the template's guidance note after the contents table --------
    tbl = d.tables[0]._tbl
    el = tbl.getnext()
    while el is not None:
        nxt = el.getnext()
        if el.tag != qn("w:sectPr"):
            body.remove(el)
        el = nxt
    return contents


APPENDIX_ROWS = [("A.", "Appendix A - Source Code of Q1, Q2 and safe_string.h", "appA"),
                 ("B.", "Appendix B - Complete Test Table for the Twenty Examples", "appB")]


def fill_contents_table(rep):
    t = rep.d.tables[0]
    if len(t.rows) == 19:               # add the two appendix rows (copies of row 18)
        for si, title, _ in APPENDIX_ROWS:
            new = copy.deepcopy(t.rows[-1]._tr)
            t._tbl.append(new)
            row = t.rows[-1]
            for cell, text in zip(row.cells[:2], (si, title)):
                p = cell.paragraphs[0]
                p.runs[0].text = text
                for r in p.runs[1:]:
                    r._r.getparent().remove(r._r)
    for row in t.rows:                  # template table text in Times New Roman
        for cell in row.cells:
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.name = SERIF
    keys = ["abstract", "contents", "lof"] + [f"s{i}" for i in range(4, 19)] + ["appA", "appB"]
    for row, key in zip(t.rows[1:], keys):
        cell = row.cells[2]
        p = cell.paragraphs[0]
        for r in p.runs:
            r._r.getparent().remove(r._r)
        r = p.add_run(rep.page(key))
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER


# =============================================================================
# Content
# =============================================================================
ABSTRACT = (
    "C stores text in plain character arrays, and the classic library functions "
    "strcpy, strcat, sprintf, gets and scanf(\"%s\") never check the size of the "
    "destination or the trustworthiness of their input. This project demonstrates "
    "these string vulnerabilities in deliberately unsafe programs and removes them "
    "with a layered design: bounded input handling, whitelist validation, length and "
    "boundary checks, a small safe-string library (safe_copy, safe_concat, "
    "safe_format) that always terminates and reports truncation, output verification "
    "and fixed format strings. Two in-depth case studies (strcpy/strcat overflow and "
    "format-string/input-validation flaws) and twenty smaller examples, from off-by-one "
    "loops to command injection, use-after-free and strtok, each exist in a "
    "vulnerable and a secure version. Every program was compiled four ways and tested "
    "with normal, boundary, invalid and oversized inputs. The vulnerable builds "
    "overwrote a neighbouring struct field, overwrote the return address, leaked a "
    "simulated secret and crashed; the secure builds passed all {grand} automated tests "
    "under AddressSanitizer. gcc, Cppcheck, a banned-API scanner, AddressSanitizer and "
    "Valgrind report no findings in the secure code, and the comparison shows which "
    "bug classes each tool misses."
)


def section_abstract(rep, contents_p):
    """Insert the Abstract before the template's Contents paragraph."""
    h = rep.d.add_paragraph(style="Heading 1")
    h.paragraph_format.page_break_before = True
    h.add_run("1. Abstract")
    text = ABSTRACT.format(grand=f"{GRAND_PASS}/{GRAND_TOTAL}")
    words = len(text.split())
    assert 150 <= words <= 200, words
    p1 = rep.para(text)
    p2 = rep.para("**Keywords:** string vulnerabilities, buffer overflow, format string, "
                  "input validation, secure coding in C, AddressSanitizer, Cppcheck, Valgrind, CWE.")
    for p in (h, p1, p2):                 # move them in front of "Contents"
        contents_p._p.addprevious(p._p)
    return words


def section_lof(rep, figs, tabs):
    rep.h1("3. List of Figures and Tables")
    for n, (kind, items) in enumerate((("Figures", figs), ("Tables", tabs)), 1):
        rep.h2(f"3.{n} List of {kind}")
        for label, cap in items:
            p = rep.d.add_paragraph(style="Report Body")
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.left_indent = Cm(2.3)
            p.paragraph_format.first_line_indent = Cm(-2.3)
            p.paragraph_format.tab_stops.add_tab_stop(Cm(2.3))
            p.paragraph_format.tab_stops.add_tab_stop(Cm(TEXT_WIDTH_CM), WD_TAB_ALIGNMENT.RIGHT,
                                                      WD_TAB_LEADER.DOTS)
            short = cap if len(cap) <= 88 else cap[:85].rsplit(" ", 1)[0] + " ..."
            r = p.add_run(f"{kind[:-1]} {label}\t")
            r.font.size = Pt(10.5)
            r = p.add_run(f"{short}\t{rep.page(kind[0] + label)}")
            r.font.size = Pt(10.5)


def sections_4_to_8(rep):
    # ------------------------------------------------------------------ 4
    rep.h1("4. Introduction")
    rep.para(
        "A C string is an array of `char` that ends with a zero byte (`'\\0'`). Nothing in the "
        "language records how large the array is, so every function that writes a string "
        "must be told the size of the destination - and the classic library functions "
        "(`strcpy`, `strcat`, `sprintf`, `gets`, `scanf(\"%s\")`) are not told. When the input "
        "is longer than expected, the extra bytes are written over whatever lies next to the "
        "buffer: other variables, the saved frame pointer or the return address. A second "
        "family of bugs comes from trusting the content of input: text used as a `printf` "
        "format string, numbers converted with unchecked `scanf(\"%d\")` or `atoi`, file names "
        "containing `../`, or names containing shell metacharacters.")
    rep.para(
        "Memory-safety errors of this kind remain one of the largest sources of security "
        "vulnerabilities in C/C++ software; the Phase-I literature survey quotes that about 70% "
        "of security bugs in Microsoft products are memory-safety errors and that large C/C++ "
        "code bases will stay in use [1]. This project, carried out for the course "
        "24CYE551 Secure Coding Using C/C++, implements and evaluates practical prevention "
        "methods for string vulnerabilities at the source-code level.")
    rep.para(
        "The work is organised around the Phase-I design: a six-stage workflow (User Input, "
        "Input Validation, Length and Boundary Checking, Safe String Handling, Output "
        "Verification, Result) and five modules (Input Handling, Validation, Safe String "
        "Operations, Vulnerability Detection/Analysis, Testing and Evaluation). Two coding "
        "questions are studied in depth - **Q1**, buffer overflow through `strcpy`/`strcat`, and "
        "**Q2**, improper input validation and unsafe formatting - and twenty further small "
        "examples cover the remaining common string-related weaknesses. Every program exists "
        "in a vulnerable and a secure version, and every result in this report comes from "
        "compiling and running them.")

    # ------------------------------------------------------------------ 5
    rep.h1("5. Problem Statement")
    rep.para(
        "Programs written in C routinely copy, concatenate and format strings that come from "
        "users, files and command-line arguments. The standard functions used for this do not "
        "check buffer sizes, do not guarantee termination in every case (`strncpy`), cannot "
        "report errors (`atoi`) or interpret their input as instructions (`printf(user_input)`, "
        "`system()`). The result is a set of well-known weaknesses - buffer overflow (CWE-120, "
        "CWE-121, CWE-787), off-by-one errors (CWE-193), externally controlled format strings "
        "(CWE-134), improper input validation (CWE-20) and related memory errors.")
    rep.para(
        "The problem addressed by this project is therefore: **how can C programs that handle "
        "untrusted strings be written so that over-long, malformed or malicious input is "
        "detected and rejected before it can corrupt memory, leak data or change the program's "
        "behaviour - and how can this be demonstrated and verified?** The solution must work "
        "with standard C (C11) and the usual toolchain (gcc, Make), must not depend on any one "
        "detection tool, and must be checked with reproducible tests that compare vulnerable "
        "and protected code.")

    # ------------------------------------------------------------------ 6
    rep.h1("6. Objectives")
    rep.para("The objectives were defined in Phase I and have all been carried out:")
    rep.bullets([
        "Study common string vulnerabilities (buffer overflow, improper validation, unsafe "
        "formatting) and their causes.",
        "Identify unsafe string-handling practices and functions in C code (Q1, Q2 and 20 examples).",
        "Implement input validation and boundary-checking techniques (whitelists, length and "
        "range limits, strict number parsing).",
        "Apply safer string-handling methods: a library of bounded copy, concatenation and "
        "formatting functions that always terminate and report truncation.",
        "Use static analysis (gcc warnings, Cppcheck, a banned-API scan) and dynamic analysis "
        "(AddressSanitizer, UBSan, Valgrind) to find vulnerabilities.",
        f"Evaluate the solution with normal, boundary, invalid and oversized test cases "
        f"({GRAND_TOTAL} automated tests).",
        "Compare the behaviour of vulnerable and protected code for every test case.",
    ], numbered=True)

    # ------------------------------------------------------------------ 7
    rep.h1("7. Literature Review / Existing System")
    rep.h2("7.1 Literature Review")
    rep.para(
        "The Phase-I literature survey reviewed six recent IEEE/ACM publications. The "
        "paragraphs below summarise what each paper does and how it relates to string "
        "vulnerabilities; the figures quoted are the results reported by the authors.")
    lit = [
        ("[1] Memory tagging using cryptographic integrity on commodity x86 CPUs (Schrammel et al., IEEE EuroS&P 2024).",
         "The authors add memory tagging to ordinary x86 processors to catch spatial and temporal "
         "heap errors in C/C++. Their system, IntegriTag, uses Intel TME-MK key IDs as tags and "
         "flags a bad access when an integrity check fails; a custom allocator and kernel patch "
         "are required. They report detection of all NIST Juliet test cases for CWE-122, CWE-415 "
         "and CWE-416 with a 32-41% run-time overhead. The work is not string-specific, but heap "
         "buffer overruns are the root of many string overflows, and the authors note that "
         "string functions such as strlen over-read and needed glibc changes. It also shares a "
         "limitation we observed with AddressSanitizer: intra-object overflows are out of scope."),
        ("[2] Precise sparse abstract execution via cross-domain interaction (Cheng, Wang and Sui, ICSE 2024).",
         "This paper makes sparse static analysis more precise by letting a pointer domain and "
         "an interval domain refine each other, and applies it to buffer-overflow and null-"
         "dereference checking, including library calls such as memcpy, fgets and fscanf. On ten "
         "real projects the authors report 111 real bugs at 68.51% precision. It is a model for "
         "our detection module: static analysis that reasons about buffer sizes can flag unsafe "
         "string-function use before the program runs - exactly what Cppcheck could not do for "
         "our strcpy/strcat cases."),
        ("[3] RISC-V based secure processor architecture for return address protection (Sharma and Goel, VLSID 2025).",
         "The authors protect return addresses against stack-buffer-overflow attacks by "
         "extending the processor's Return Address Stack into reserved memory and checking every "
         "return against it. They report under 0.1% memory overhead and detection of RIPE "
         "attacks that use memcpy and strcpy. Their motivating example is a strcpy overflow that "
         "overwrites the return address - the same effect our Q1 vulnerable program showed "
         "(Valgrind: jump to 0x4141414141414141). It is a hardware defence-in-depth layer, "
         "complementary to fixing the source code."),
        ("[4] SaTC: Shared-keyword aware taint checking for detecting bugs in embedded systems (Chen et al., IEEE TDSC 2024).",
         "SaTC locates user-input entry points in IoT firmware through keywords shared by the web "
         "front-end and back-end binaries, then tracks the input with taint analysis to risky "
         "sinks such as memcpy-like and system-like functions. The authors report 36 previously "
         "unknown bugs in 39 firmware samples, most of them command injection. This supports our "
         "input-validation and analysis modules: untrusted strings flowing into strcpy, "
         "printf or system() are the pattern behind our Q1, Q2 and command-injection examples."),
        ("[5] SOLDER: Retrofitting legacy code with cross-language patches (Williams, Gavazzi and Kirda, SANER 2023).",
         "SOLDER patches vulnerable legacy C/C++ functions by swapping them, at LLVM bitcode "
         "level, for versions written in a safer language such as Rust, and tests the patch with "
         "KLEE. The authors report mitigating 11 known CVEs in five code bases, including a "
         "Mosquitto stack overflow and an Apache string-escaping bug. It relates to our approach "
         "of replacing unsafe string-handling functions with safer ones; we do this inside C with "
         "a safe-string library rather than across languages."),
        ("[6] Towards secure code generation with LLMs: A study on common weakness enumeration (Zhao et al., IEEE TSE 2025).",
         "This study reduces weaknesses in AI-generated code: SecureCoder summarises the code's "
         "logic, matches it to CWE entries, generates security guidelines and then regenerates "
         "safer code. The authors report that more than 65% of the vulnerabilities in Copilot-"
         "generated code were mitigated. Its CWE-based guidance, which includes buffer weaknesses "
         "such as CWE-119 and CWE-787, matches our use of CWE IDs to classify every bug and its fix."),
    ]
    for title, text in lit:
        rep.para(f"**{title}** {text}")
    rep.h2("7.2 Existing System")
    rep.para(
        "In existing C code, string safety is usually left to the individual programmer. The "
        "standard library offers only partial help: `strncpy` and `strncat` take a size but "
        "`strncpy` may leave the result unterminated and neither reports truncation; "
        "`snprintf` is bounded but its return value is often ignored; `gets` was removed from "
        "C11 but still links; and the optional bounds-checking interfaces of C11 Annex K "
        "(`strcpy_s` and similar) are not provided by glibc [10]. Tool support exists - compiler "
        "warnings and `_FORTIFY_SOURCE` [14], static analysers such as Cppcheck [13], and "
        "run-time checkers such as AddressSanitizer [11] and Valgrind [12] - but each covers "
        "only some bug classes, as Section 14 shows. Coding standards such as SEI CERT C [8] "
        "and the CWE catalogue [7] describe the rules, and secure-coding texts [9] explain the "
        "attacks, but a project still has to turn them into code, tests and evidence. This "
        "project does that for string handling.")

    # ------------------------------------------------------------------ 8
    rep.h1("8. Proposed System")
    rep.para(
        "The proposed system is a set of C programs and a reusable library that apply the "
        "Phase-I workflow to every piece of untrusted text. Each vulnerable program has a "
        "secure counterpart that performs the same task, so the effect of every prevention "
        "method can be measured directly. The key design decision is **truncate safely, report, "
        "and reject**: the library never writes past a buffer and always terminates it, but it "
        "returns `SS_TRUNCATED` or `IN_TOO_LONG` instead of silently cutting the data, and the "
        "programs treat that status as a rejection.")
    rep.h2("8.1 Security Requirements and Threats")
    rep.table("8.1", "Security requirements and the threats they address",
              ["Threat (untrusted input)", "Security requirement", "Mechanism in the secure code"],
              [
                  ["Over-long string overflows a buffer (CWE-120/121/787)", "No write may go past a buffer; the result must be terminated", "safe_copy / safe_concat / safe_format with sizeof(buffer); reject on SS_TRUNCATED"],
                  ["Off-by-one: no room for '\\0' (CWE-193, CWE-170)", "Maximum length = buffer size - 1", "length checks with >=, explicit terminator, validate_input max_len"],
                  ["Text used as a format string (CWE-134)", "User data must never be a format", "fixed format strings: printf(\"%s\", msg); -Wformat=2 -Werror"],
                  ["Malformed numbers, overflow, out-of-range values (CWE-20/190/252)", "Every conversion is checked; values are range-limited", "validate_integer (digits only, range, ERANGE)"],
                  ["Unexpected characters (shell, path, markup) (CWE-20/78/22)", "Only whitelisted characters are accepted", "validate_input with character classes + explicit extras"],
                  ["Unbounded or desynchronised input (CWE-242)", "Input is read in bounded lines; over-long lines are drained", "input_read_line (fgets), input_from_arg, input_read_file"],
                  ["Corruption of neighbouring data", "Results are verified before use", "output verification (terminated buffers, role still \"guest\")"],
                  ["Memory-management errors (CWE-415/416/690)", "One owner, one free, checked allocation", "single clean-up point, NULL after free, malloc result checked"],
              ], [4.6, 5.0, 6.4])
    rep.h2("8.2 Secure Coding Practices")
    rep.para("Table 8.2 lists the secure-coding practices applied in the secure programs, with "
             "the corresponding SEI CERT C rules [8].")
    rep.table("8.2", "Secure coding practices applied",
              ["Practice", "How it is applied", "CERT C"],
              [
                  ["Bounded string operations", "every copy, concatenation and format takes the total buffer size", "STR31-C, STR07-C"],
                  ["Guaranteed termination", "the library always writes '\\0', even on error", "STR32-C"],
                  ["Whitelist input validation", "allowed characters, minimum/maximum length and numeric ranges checked before use", "-"],
                  ["Strict number parsing", "validate_integer replaces atoi and unchecked scanf(\"%d\")", "ERR34-C"],
                  ["Fixed format strings", "user text is only ever an argument, never the format", "FIO30-C, FIO47-C"],
                  ["Check every return value", "any library status other than OK is a rejection", "ERR33-C"],
                  ["No dangerous functions", "no gets, strcpy, strcat, sprintf, system() with user text or strtok; enforced by the banned-API scan in CI", "MSC24-C"],
                  ["Compiler hardening", "-Werror -Wformat=2 -Wconversion, FORTIFY_SOURCE=2, stack protector, PIE, full RELRO", "-"],
                  ["Defence in depth", "validation, bounded operations, output verification, sanitizers and tests", "-"],
              ], [4.2, 9.0, 3.0])


def sections_9_to_11(rep):
    # ------------------------------------------------------------------ 9
    rep.h1("9. System Architecture / Workflow")
    rep.para(
        "Every secure program follows the same six-stage workflow (Figure 9.1). Input enters "
        "only through bounded readers, is validated against a whitelist and length/range "
        "limits, is processed only with bounded operations whose status is checked, and the "
        "result is verified before it is printed through fixed format strings. A failure at "
        "any stage ends the program with `REJECTED: <reason>` and exit code 2; nothing derived "
        "from the bad input is used.")
    rep.figure(os.path.join(FIGS, "workflow.png"), "9.1",
               "Prevention workflow used by every secure program")
    rep.para(
        "Figure 9.2 shows how the five Phase-I modules map to the code. Modules 1-3 (Input "
        "Handling, Validation, Safe String Operations) form the library in `src/lib/`, which "
        "every secure program links. The Makefile builds four variants of every program; "
        "Module 4 (Vulnerability Detection/Analysis) and Module 5 (Testing and Evaluation) "
        "run on those builds, and GitHub Actions repeats both on every push.")
    rep.figure(os.path.join(FIGS, "architecture.png"), "9.2",
               "Module architecture and build / test / analysis pipeline")
    rep.table("9.1", "Phase-I modules and their implementation",
              ["Module", "Implementation", "Main functions / files"],
              [
                  ["1. Input Handling", "Bounded reads from stdin, argv and files", "input_read_line, input_from_arg, input_read_file (src/lib/input_handler.c)"],
                  ["2. Validation", "Whitelist, length, format and range checks", "validate_input, validate_integer (src/lib/safe_string.c)"],
                  ["3. Safe String Operations", "Bounded copy / concatenation / formatting", "safe_copy, safe_concat, safe_format, safe_strlen"],
                  ["4. Vulnerability Detection / Analysis", "Static and dynamic analysis of both versions", "analysis/run_analysis.sh, analysis/banned_functions.py"],
                  ["5. Testing and Evaluation", "Unit and scenario tests on four builds", "tests/*.c, tests/scenarios/*.sh, tests/run_tests.sh"],
              ], [4.0, 5.5, 6.5])

    # ------------------------------------------------------------------ 10
    rep.h1("10. Tools and Technologies Used")
    rep.table("10.1", "Tools and technologies (versions from the project environment)",
              ["Tool / technology", "Version", "Purpose"],
              [
                  ["C language (C11)", "-std=c11", "Implementation language of all programs and the library"],
                  ["GCC", GCC.replace("gcc ", ""), "Compiler; warnings, FORTIFY_SOURCE, stack protector, sanitizers"],
                  ["GNU Make", MAKE.replace("GNU Make ", ""), "Build automation (all, vulnerable, secure, asan, examples, test, analyze)"],
                  ["AddressSanitizer + UBSan", "bundled with GCC 13.3", "Run-time detection of overflows, use-after-free, double free, UB"],
                  ["Valgrind (Memcheck)", VALGRIND.replace("valgrind-", ""), "Run-time detection of invalid accesses, uninitialised values, leaks"],
                  ["Cppcheck", CPPCHECK.replace("Cppcheck ", ""), "Static analysis of C code"],
                  ["Python 3", "3.12 (CI) / 3.14 (Codespace)", "Banned-API scanner, report generation"],
                  ["Bash", "-", "Scenario test scripts, analysis script"],
                  ["Git and GitHub", "-", "Version control, one commit per phase"],
                  ["GitHub Actions", "ubuntu-24.04 runner", "Continuous integration: build, test, analysis gates"],
                  ["GitHub Codespaces", "Ubuntu 24.04.5 LTS", "Isolated development and test environment"],
              ], [4.2, 3.6, 8.2])

    # ------------------------------------------------------------------ 11
    rep.h1("11. Methodology")
    rep.para("The project was carried out in six review-gated phases, each compiled, run, "
             "committed and pushed before the next began, followed by the twenty examples:")
    rep.bullets([
        "**Phase 1** - repository skeleton, Makefile with separate vulnerable/secure/ASan builds, README.",
        "**Phase 2** - safe-string library and input handler with unit tests (guard bytes, ASan).",
        "**Phase 3** - Q1: strcpy/strcat overflow, vulnerable and secure versions, 17 scenario tests.",
        "**Phase 4** - Q2: input validation and format strings, vulnerable and secure versions, 26 tests.",
        "**Phase 5** - analysis script (gcc, Cppcheck, banned-API scan, ASan, Valgrind) and CI.",
        "**Phase 6** - report from real outputs; then 20 additional examples with 90 tests.",
    ], numbered=False)
    rep.para(
        "**Test design.** Every test case belongs to one of four categories - Normal, Boundary "
        "(exactly at and one past each limit), Invalid (malformed or malicious input) and "
        "Oversized (far beyond every limit). Each case is run on **four builds** of the same "
        "program: vulnerable, vulnerable with ASan, secure and secure with ASan. A case passes "
        "only when the secure build gives the expected result (accept, reject or usage error), "
        "its output is correct for accepted input, and the secure ASan build reports no error. "
        "The vulnerable columns record what actually happened, so every table is a direct "
        "comparison.")
    rep.para(
        "**Checking the tests themselves.** Two controls make sure the tests can fail: a "
        "mutation check (a copy of `safe_copy` with its bound removed fails 5 unit tests) and "
        "negative controls (the vulnerable binaries are tested as if they were the secure "
        "ones; the suites must then fail - Table 14.9).")
    rep.h2("11.1 Vulnerability Identification")
    rep.para("Each weakness was identified by reading the code, then confirmed by running the "
             "vulnerable build. Table 11.1 maps the bugs of the two case studies to their CWE IDs; "
             "the CWE IDs of the twenty examples are listed in Table 12.3.")
    rep.table("11.1", "Vulnerabilities in the Q1/Q2 programs and their CWE IDs",
              ["Bug", "Vulnerable code", "CWE", "Observed effect (vulnerable build)"],
              [
                  ["Q1-B1", "strcpy(acct.username, argv[1])", "CWE-120, CWE-787, CWE-193", "16 chars wipe role (off-by-one); 20 chars overwrite role with \"AAAA\""],
                  ["Q1-B2", "strcat(greeting, acct.username)", "CWE-120, CWE-787", "stack-buffer-overflow on greeting (24+ chars)"],
                  ["Q1-B3", "strcpy/strcat chain into path[32]", "CWE-121", "greeting corrupted; 100 chars overwrite the return address"],
                  ["Q1-B4", "no validation of argv", "CWE-20", "\"bob;ls\", empty names and spaces accepted"],
                  ["Q2-B1", "scanf(\"%s\", name / msg)", "CWE-120, CWE-242", "40-char name: SIGSEGV; \"John Smith\" split into two fields"],
                  ["Q2-B2", "scanf(\"%d\", &age) unchecked, no range", "CWE-252, CWE-20, CWE-457, CWE-190", "\"abc\" shifts into the message; -5 accepted; 20 digits -> age=-1"],
                  ["Q2-B3", "sprintf(record, ...) into record[64]", "CWE-120, CWE-787", "ASan: WRITE of size 83 into record[64]"],
                  ["Q2-B4", "printf(msg)", "CWE-134, CWE-200", "%p prints stack values; %27$lx leaks the simulated secret; %s x 8 crashes"],
              ], [1.4, 4.6, 3.8, 6.2])


def snippet(path, start_pat, end_pat=None, n=None):
    lines = read(os.path.join(ROOT, path)).split("\n")
    i = next(k for k, l in enumerate(lines) if re.search(start_pat, l))
    if n:
        return lines[i:i + n]
    j = next(k for k in range(i + 1, len(lines)) if re.search(end_pat, lines[k]))
    return lines[i:j + 1]


def section_12(rep):
    rep.h1("12. Implementation / Project Development")
    rep.para(
        f"The implementation consists of the safe-string library, the Q1 and Q2 case studies "
        f"and twenty small examples. Only key snippets are shown here; the complete source "
        f"code is in Appendix A.")
    files = [
        ("src/lib/safe_string.h / .c", loc("src/lib/safe_string.h") + loc("src/lib/safe_string.c"), "Validation + safe string operations (Modules 2, 3)"),
        ("src/lib/input_handler.h / .c", loc("src/lib/input_handler.h") + loc("src/lib/input_handler.c"), "Bounded input (Module 1)"),
        ("src/vulnerable/q1_overflow.c", loc("src/vulnerable/q1_overflow.c"), "Q1 vulnerable"),
        ("src/secure/q1_overflow.c", loc("src/secure/q1_overflow.c"), "Q1 secure"),
        ("src/vulnerable/q2_format.c", loc("src/vulnerable/q2_format.c"), "Q2 vulnerable"),
        ("src/secure/q2_format.c", loc("src/secure/q2_format.c"), "Q2 secure"),
        ("src/examples/*/vulnerable.c (20)", sum(loc(f[len(ROOT) + 1:]) for f in glob.glob(os.path.join(ROOT, "src/examples/*/vulnerable.c"))), "20 vulnerable examples"),
        ("src/examples/*/secure.c (20)", sum(loc(f[len(ROOT) + 1:]) for f in glob.glob(os.path.join(ROOT, "src/examples/*/secure.c"))), "20 secure examples"),
    ]
    rep.table("12.1", "Source files (line counts including comments)",
              ["File", "Lines", "Role"], [[a, b, c] for a, b, c in files], [6.2, 1.6, 8.2], mono_cols=(0,))

    rep.h2("12.1 Safe String Library")
    rep.para(
        "All library functions take the **total** size of the destination, never write past "
        "it, always leave a terminating `'\\0'` and report truncation through their return "
        "value. Sizes of zero or larger than `SS_MAX_SIZE` (`SIZE_MAX >> 1`) are rejected, "
        "because such a size usually comes from a negative `int` converted to `size_t` (CWE-195).")
    rep.table("12.2", "Safe-string library API",
              ["Function", "Replaces", "Result codes"],
              [
                  ["safe_copy(dst, size, src)", "strcpy, strncpy", "SS_OK, SS_TRUNCATED, SS_ERR_NULL, SS_ERR_SIZE"],
                  ["safe_concat(dst, size, src)", "strcat, strncat", "as above + SS_ERR_UNTERMINATED"],
                  ["safe_format(dst, size, fmt, ...)", "sprintf", "as above + SS_ERR_FORMAT; printf format attribute"],
                  ["safe_strlen(s, max)", "strlen on untrusted data", "length, never reads more than max bytes"],
                  ["validate_input(s, min, max, set, extra, &pos)", "ad-hoc checks", "VAL_OK, VAL_ERR_EMPTY, VAL_ERR_TOO_LONG, VAL_ERR_BAD_CHAR"],
                  ["validate_integer(s, min, max, &out)", "atoi, scanf(\"%d\")", "VAL_OK, VAL_ERR_NOT_NUMBER, VAL_ERR_RANGE"],
                  ["input_read_line(fp, buf, size, &len)", "gets, scanf(\"%s\")", "IN_OK, IN_TOO_LONG (line drained), IN_EOF, IN_ERR_NUL_BYTE"],
                  ["input_from_arg(argc, argv, i, buf, size)", "strcpy(buf, argv[i])", "IN_OK, IN_TOO_LONG, IN_ERR_MISSING"],
                  ["input_read_file(path, buf, size, &len)", "unchecked fread", "IN_OK, IN_TOO_LONG, IN_ERR_IO"],
              ], [6.0, 3.6, 6.4], mono_cols=(0,))
    rep.para("The core of `safe_copy` (src/lib/safe_string.c):")
    rep.code(snippet("src/lib/safe_string.c", r"^ss_status safe_copy", r"^}"))

    rep.h2("12.2 Q1 - Buffer Overflow via strcpy / strcat")
    rep.para(
        "`q1_overflow <username> <department>` builds an account record: the username is "
        "copied into `username[16]`, which is directly followed by `role[16]` in a struct, and "
        "a greeting (`greeting[32]`) and home-directory path (`path[32]`) are assembled. The "
        "vulnerable version uses `strcpy`/`strcat` with no checks:")
    rep.code(snippet("src/vulnerable/q1_overflow.c", r"\[B1\] No length check", r"strcat\(path, acct.username\)"))
    rep.para("The secure version follows the workflow and rejects any truncation:")
    rep.code(snippet("src/secure/q1_overflow.c", r"---- \[3\]\+\[4\] Length checks", r"return reject\(\"home directory path\", msg\);") + ["    }"])

    rep.h2("12.3 Q2 - Input Validation and Unsafe Formatting")
    rep.para(
        "`q2_format` is a feedback form that reads a name, an age and a message from standard "
        "input. The vulnerable version uses `scanf(\"%s\")`, an unchecked `scanf(\"%d\")`, "
        "`sprintf` and `printf(msg)`; a simulated `secret_token` on the stack shows the "
        "information leak:")
    rep.code(snippet("src/vulnerable/q2_format.c", r'printf\("Name: "\);', r'printf\("Saved record'))
    rep.para("The secure version reads whole lines, validates every field and uses fixed format strings:")
    rep.code(snippet("src/secure/q2_format.c", r"v = validate_integer\(age_in", r"\}") +
             [""] + snippet("src/secure/q2_format.c", r"st = safe_format\(record", r"\}") +
             [""] + snippet("src/secure/q2_format.c", r"---- \[6\] Result", r'printf\("Saved record'))

    rep.h2("12.4 Twenty Additional Examples")
    rep.para(
        "`src/examples/eNN_name/` contains twenty small, self-contained pairs (`vulnerable.c` "
        "with the bug marked `BUG:`, `secure.c` with the fix marked `FIX:`), covering the "
        "remaining common string-related weaknesses. Examples 1-4 repeat the Q1/Q2 bug "
        "classes in their smallest form so all twenty can be compared side by side.")
    rep.table("12.3", "The twenty examples: weakness, CWE, bug and fix",
              ["#", "Example", "Weakness", "CWE", "Bug (vulnerable.c)", "Fix (secure.c)"],
              [[i, e[0], e[1], e[2], e[3], e[4]] for i, e in enumerate(EXAMPLES, 1)],
              [0.7, 4.0, 2.9, 2.0, 3.2, 3.2], size=8.5)
    rep.para("Two representative fixes - example 9 (integer overflow in a length calculation) "
             "and example 20 (`strtok` replaced by `strtok_r`):")
    rep.code(snippet("src/examples/e09_length_integer_overflow/secure.c", r"la = strlen\(argv\[1\]\);", r"stored = \(unsigned char\)total;"))
    rep.code(snippet("src/examples/e20_strtok_reentrancy/secure.c", r"for \(pair = strtok_r", r"count\+\+;") + ["    }"])

    rep.h2("12.5 Implementation and Security Testing")
    rep.para(
        "Security testing is built into the implementation. The unit tests place guard bytes "
        "after every buffer and check that they are unchanged, and they run under "
        "AddressSanitizer + UBSan. The scenario tests run every case on the four builds and "
        "check the result, the output and the absence of sanitizer reports. `make test` runs "
        "all suites (Table 12.4), `make analyze` runs the five analysis checks, and the "
        "GitHub Actions workflow repeats both on every push and fails if the secure code has "
        "any finding.")
    rep.table("12.4", "Test suites",
              ["Suite", "What it tests", "Cases"],
              [
                  ["tests/test_safe_string.c", "safe_strlen, safe_copy, safe_concat, safe_format, validate_input, validate_integer", TOTALS["safe_string"][1]],
                  ["tests/test_input_handler.c", "input_read_line, input_from_arg, input_read_file", TOTALS["input_handler"][1]],
                  ["tests/scenarios/q1_overflow.sh", "Q1 vulnerable vs secure, 4 builds per case", TOTALS["q1_overflow"][1]],
                  ["tests/scenarios/q2_format.sh", "Q2 vulnerable vs secure, 4 builds per case", TOTALS["q2_format"][1]],
                  ["tests/scenarios/examples.sh", "20 examples, 4 builds per case", TOTALS["examples"][1]],
                  ["Total (make test)", "", GRAND_TOTAL],
              ], [5.4, 8.6, 2.0], mono_cols=(0,))


def section_13(rep):
    rep.h1("13. Experimental Setup")
    rep.table("13.1", "Experimental environment",
              ["Item", "Value"],
              [
                  ["Platform", "GitHub Codespaces container, Ubuntu 24.04.5 LTS"],
                  ["Kernel", KERNEL],
                  ["Hardware", "4 vCPUs, 15 GB RAM (x86-64)"],
                  ["Compiler", GCC],
                  ["Static analysis", CPPCHECK + "; analysis/banned_functions.py"],
                  ["Dynamic analysis", "AddressSanitizer + UBSan (GCC 13.3), " + VALGRIND],
                  ["Build", MAKE],
                  ["CI", "GitHub Actions, ubuntu-24.04 runner"],
              ], [4.0, 12.0])
    rep.table("13.2", "Build configurations (Makefile)",
              ["Build", "Output", "Key flags", "Purpose"],
              [
                  ["vulnerable", "bin/vulnerable/, bin/examples/*/vulnerable", "-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0", "protections off so the bugs are observable"],
                  ["secure", "bin/secure/, bin/examples/*/secure", "-Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wconversion -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -z relro -z now", "warnings are errors + hardening"],
                  ["asan", "bin/asan/, bin/examples/*/*_asan", "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0", "run-time detection"],
              ], [2.0, 4.0, 6.4, 3.6], size=8.5)
    rep.para(
        "FORTIFY_SOURCE is disabled in the ASan build because Ubuntu's gcc enables it at -O1 "
        "and it would abort before ASan can report. Each experiment runs `make all asan`, "
        "`make test` and `make analyze`.")
    rep.h2("13.1 Ethical Considerations")
    rep.bullets([
        "All development and testing ran inside an isolated GitHub Codespace container and on "
        "GitHub's isolated CI runners; no real systems, networks or third-party data were involved.",
        "The vulnerable programs, each labelled as a deliberately insecure teaching example, read "
        "only local input (arguments, redirected standard input, repository test files) and were "
        "never deployed.",
        "No exploit payloads were used: overflow tests use runs of the letter 'A', the "
        "format-string tests only read memory (%p, %lx, %s) and never use %n, the "
        "command-injection test only runs `echo INJECTED`, and the path-traversal test reads a "
        "test fixture containing a dummy value; the \"secret\" leaked in Q2 is a simulated "
        "constant in our own program.",
    ])


def section_14(rep):
    rep.h1("14. Results and Analysis")
    rep.h2("14.1 Overall Test Results")
    rep.para(f"`make test` ran all suites; **{GRAND_PASS} of {GRAND_TOTAL} tests passed** "
             f"(Table 14.1, Figure 15.20).")
    rep.table("14.1", "Overall test summary (make test)",
              ["Suite", "Passed", "Total", "Result"],
              [[k, p, t, "PASS" if p == t else "FAIL"] for k, (p, t) in TOTALS.items()] +
              [["TOTAL", GRAND_PASS, GRAND_TOTAL, GRAND_RESULT]],
              [6.0, 2.5, 2.5, 2.5])
    # unit tests by function and category
    groups = [("SL", "safe_strlen"), ("SC", "safe_copy"), ("CC", "safe_concat"), ("SF", "safe_format"),
              ("VI", "validate_input"), ("VN", "validate_integer"), ("RL", "input_read_line"),
              ("AR", "input_from_arg"), ("RF", "input_read_file")]
    rows = []
    for pre, name in groups:
        rs = [r for r in UNIT_SS + UNIT_IH if r[0].startswith(pre + "-")]
        cnt = lambda c: sum(1 for r in rs if r[1] == c)
        rows.append([name, cnt("Normal"), cnt("Boundary"), cnt("Invalid"), cnt("Oversized"),
                     f"{sum(1 for r in rs if r[5] == 'PASS')}/{len(rs)}"])
    rep.table("14.2", "Unit tests by function and category (all run under ASan + UBSan)",
              ["Function", "Normal", "Boundary", "Invalid", "Oversized", "Passed"], rows,
              [4.4, 2.2, 2.2, 2.2, 2.4, 2.4], mono_cols=(0,))

    def qtable(label, cap, rows):
        rep.table(label, cap, ["ID", "Category", "Input", "Vulnerable (plain)", "Vulnerable (ASan)",
                               "Expected", "Secure result", "Result"],
                  [[r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[8]] for r in rows],
                  [1.35, 1.9, 2.4, 2.4, 2.55, 1.8, 2.5, 1.3])

    rep.h2("14.2 Q1 - Vulnerable vs Secure")
    q1d = defect_q(Q1)
    rep.para(
        f"In {q1d} of {len(Q1)} Q1 cases the vulnerable program corrupted memory, crashed or "
        f"accepted invalid input; the secure program gave the expected result in "
        f"{TOTALS['q1_overflow'][0]} of {TOTALS['q1_overflow'][1]} cases with no ASan report. "
        f"The most important observations (Figures 15.7-15.12, 15.21):")
    rep.bullets([
        "16 characters wipe the neighbouring `role` field (off-by-one) and 20 characters overwrite "
        "it with \"AAAA\" - silently, with exit code 0.",
        "A path one byte too long corrupts the neighbouring `greeting` buffer; ASan reports a "
        "stack-buffer-overflow in `strcat` (q1_overflow.c line 67).",
        "100 characters crash the program (SIGSEGV); Valgrind shows a jump to "
        "0x4141414141414141 - the return address was overwritten with the input bytes.",
        "**ASan misses the overflow inside the struct** (username into role): both fields belong "
        "to the same object, so there is no red zone between them. FORTIFY_SOURCE (-O2 "
        "-D_FORTIFY_SOURCE=2) does stop it: `*** buffer overflow detected ***`.",
    ])
    qtable("14.3", "Q1 test cases - vulnerable vs secure (from tests/scenarios/q1_overflow.sh)", Q1)

    rep.h2("14.3 Q2 - Vulnerable vs Secure")
    q2d = defect_q(Q2)
    rep.para(
        f"In {q2d} of {len(Q2)} Q2 cases the vulnerable program misbehaved; the secure program "
        f"passed {TOTALS['q2_format'][0]} of {TOTALS['q2_format'][1]}. Observations "
        f"(Figures 15.13-15.19):")
    rep.bullets([
        "`%p.%p.%p.%p` printed stack and register values; `%27$lx` printed 5ec12e7ab1e, the "
        "simulated secret_token; `%s` x 8 crashed the program (exit code 139).",
        "Even innocent text is corrupted: `50%off` printed an octal number from the stack.",
        "Unchecked `scanf(\"%d\")`: `abc` became the message, `John Smith` was split into two "
        "fields, -5 was accepted and a 20-digit number was stored as -1.",
        "`sprintf` wrote 83 bytes into `record[64]` (ASan stack-buffer-overflow).",
        "**ASan does not detect the format-string bugs** - they leak data without an invalid "
        "memory access; gcc's -Wformat-security and the banned-API scan do find printf(msg).",
        "The secure version prints `%p`, `%27$lx` and `%s%s...` literally, because user text is "
        "only ever an argument of a fixed format string.",
    ])
    qtable("14.4", "Q2 test cases - vulnerable vs secure (from tests/scenarios/q2_format.sh)", Q2)

    rep.h2("14.4 Twenty Examples - Vulnerable vs Secure")
    rows = []
    for i, e in enumerate(EXAMPLES, 1):
        rs, vul, asn, passed = example_observed(i)
        rows.append([i, e[1], "; ".join(vul) or "no visible effect", "; ".join(asn) or "nothing reported",
                     f"{passed}/{len(rs)}"])
    rep.para(
        f"Across the {len(EX)} example cases the vulnerable builds showed a defect (in the plain "
        f"or ASan build) in {EX_DEFECT} cases, and ASan/UBSan reported an error in {EX_ASAN}. "
        f"The secure builds passed {TOTALS['examples'][0]} of {TOTALS['examples'][1]}. Table 14.5 "
        f"lists the distinct observations per example; the complete 90-row table is in Appendix B.")
    rep.table("14.5", "Twenty examples - observed behaviour (distinct labels from the test run)",
              ["#", "Weakness", "Vulnerable (plain) observed", "Vulnerable (ASan) observed", "Secure"],
              rows, [0.7, 3.4, 5.0, 5.1, 1.8], size=8)
    cat_rows = [[c, *EX_BY_CAT[c][:3], f"{EX_BY_CAT[c][3]}/{EX_BY_CAT[c][0]}"]
                for c in ("Normal", "Boundary", "Invalid", "Oversized")]
    cat_rows.append(["Total", len(EX), EX_DEFECT, EX_ASAN, f"{TOTALS['examples'][0]}/{TOTALS['examples'][1]}"])
    rep.table("14.6", "Twenty examples - results by category",
              ["Category", "Cases", "Vulnerable: defect observed", "Reported by ASan/UBSan", "Secure: PASS"],
              cat_rows, [2.8, 1.8, 4.2, 4.0, 3.2])
    no_asan = [EXAMPLES[i - 1][1] for i in range(1, 21) if not example_observed(i)[2] or
               all(a.startswith("NOT DETECTED") for a in example_observed(i)[2])]
    rep.para(
        "ASan reported nothing for: " + ", ".join(no_asan) + ". These are logic and "
        "input-handling bugs, not memory errors, so only validation, review and tests find "
        "them. Example 18 (malloc(strlen(s)) without +1) shows the opposite case: the plain "
        "build prints the correct result, yet ASan reports a heap-buffer-overflow on every input.")

    rep.h2("14.5 Static and Dynamic Analysis")
    rep.para(
        "`make analyze` applies five checks to both versions of Q1 and Q2 (and the secure "
        "examples). Table 14.7 is the summary printed by the analysis script (Figure 15.24).")
    rep.table("14.7", "Analysis summary - vulnerable vs secure (analysis/run_analysis.sh)",
              ["Check", "Vulnerable version", "Secure version"], ANALYSIS_ROWS,
              [6.0, 5.2, 4.8], size=8.5)
    rep.table("14.8", "Which tool found which vulnerability (in our runs)",
              ["Vulnerability", "gcc", "Cppcheck", "Banned-API scan", "ASan", "Valgrind", "Tests"],
              [
                  ["strcpy overflow into struct field (role)", "-", "-", "yes", "no (intra-object)", "-", "yes"],
                  ["strcat overflow of path / greeting", "-", "-", "yes", "yes", "- (until crash)", "yes"],
                  ["Return address overwritten (100 chars)", "-", "-", "yes", "yes", "yes", "yes (crash)"],
                  ["scanf(\"%s\") without width", "-", "yes", "yes", "yes (on overflow)", "yes (crash)", "yes"],
                  ["Unchecked scanf(\"%d\") / no range", "yes (unused result)", "-", "yes", "-", "-", "yes"],
                  ["sprintf overflow of record", "yes", "-", "yes", "yes", "-", "yes"],
                  ["printf(msg) format string", "yes", "-", "yes", "-", "only %s crash", "yes"],
                  ["Command injection, path traversal, strtok (examples)", "-", "-", "-", "-", "not run", "yes"],
              ], [5.2, 1.7, 1.6, 2.0, 2.2, 1.9, 1.4], size=8)
    rep.para(
        "Cppcheck reported only 3 findings in the vulnerable code (two `invalidscanf` and one "
        "style note) and none of the `strcpy`, `strcat`, `sprintf` or `printf(msg)` calls, "
        "because it cannot know how long argv or stdin data will be. The banned-API scanner was "
        "added for that reason; it reports 16 findings in the vulnerable Q1/Q2 code, 15 in the "
        "vulnerable examples and 0 in all secure code (Figure 15.23).")
    rep.table("14.9", "Negative controls - vulnerable binaries tested as if they were secure",
              ["Suite", "Normal run", "Negative control", "Conclusion"],
              [[k, f"{TOTALS[k][0]}/{TOTALS[k][1]} passed", f"{NEG[k][0]}/{NEG[k][1]} passed",
                "suite detects the unsafe code"] for k in ("q1_overflow", "q2_format", "examples")],
              [3.4, 3.4, 3.6, 5.6])

    lim = rep.h2("14.6 Limitations")
    lim.paragraph_format.page_break_before = True    # one complete block, not a spill-over
    rep.bullets([
        "**ASan blind spots.** AddressSanitizer did not detect the overflow that stays inside a "
        "struct (Q1, 16-20 characters), nor any logic bug: format-string leaks, command "
        "injection, path traversal and strtok data loss. Only validation and tests caught these.",
        "**Valgrind** did not report stack-array overflows until the program crashed, because "
        "it does not track individual stack objects.",
        "**Cppcheck** missed every strcpy/strcat/sprintf/printf(msg) call in our code; the "
        "banned-API scanner is pattern-based and can miss unusual code or wrappers.",
        "The `%27$lx` stack slot that leaks the secret is specific to this build (gcc 13.3, -O0); "
        "with other compilers or flags the slot number differs.",
        "All experiments ran on one platform (x86-64, Ubuntu 24.04, gcc 13.3); other compilers, "
        "libc versions or architectures may behave differently.",
        "Validation is ASCII-only; UTF-8 names are rejected rather than supported.",
        "The library truncates safely and reports; callers must check the status (the secure "
        "programs do, and CI enforces this only through tests and review).",
        "The path-traversal fix checks the path with realpath() and then opens it; a file "
        "replaced between the two calls (a race) is not handled in this teaching example.",
    ])


SHOT_CAPTIONS = [
    ("01_toolchain_versions.png", "Toolchain versions: gcc, Cppcheck and Valgrind"),
    ("02_repo_structure.png", "Repository structure (end of the tree output)"),
    ("03_make_help.png", "Makefile targets (make help)"),
    ("04_unit_tests_safe_string.png", "Unit tests for the safe-string library (55 tests)"),
    ("05_unit_tests_input_handler.png", "Unit tests for the input handler (25 tests)"),
    ("06_valgrind_unit_tests.png", "Valgrind on the unit tests: 0 errors, no leaks"),
    ("07_q1_vuln_normal_vs_overflow.png", "Q1 vulnerable: normal input, 16 chars (role wiped) and 20 chars (role = AAAA)"),
    ("08_q1_vuln_segfault.png", "Q1 vulnerable: 100 characters cause a segmentation fault (exit 139)"),
    ("09_q1_asan_stack_overflow.png", "Q1 ASan build: stack-buffer-overflow on path[32] in strcat"),
    ("10_q1_asan_misses_intra_struct.png", "Q1 ASan build: the overflow into role inside the struct is not detected"),
    ("11_q1_secure_rejects.png", "Q1 secure: normal input accepted, bad inputs rejected with a reason"),
    ("12_q1_test_table.png", "Q1 test run: 17/17 cases pass"),
    ("13_q2_gcc_warnings.png", "Q2 vulnerable build: gcc warns about the sprintf overflow"),
    ("14_q2_vuln_format_leak.png", "Q2 vulnerable: %p prints stack values, %27$lx leaks the simulated secret"),
    ("15_q2_vuln_validation.png", "Q2 vulnerable: John Smith is split into fields, age -5 accepted"),
    ("16_q2_vuln_crash.png", "Q2 vulnerable: %s x 8 in the message crashes the program (exit 139)"),
    ("17_q2_secure.png", "Q2 secure: invalid age rejected; %p and %s printed literally"),
    ("18_q2_asan_record_overflow.png", "Q2 ASan build: sprintf writes 83 bytes into record[64]"),
    ("19_q2_test_table.png", "Q2 test run: 26/26 cases pass"),
    ("20_all_tests_summary.png", "Overall test summary: 213/213 tests pass"),
    ("21_q1_valgrind_ret_overwrite.png", "Valgrind: jump to 0x4141414141414141 - return address overwritten (Q1, 100 chars)"),
    ("22_cppcheck_before_after.png", "Cppcheck: findings in the vulnerable code (top), none in the secure code and library (bottom)"),
    ("23_banned_api_scan.png", "Banned-API scan: 16 findings in vulnerable code, 0 in secure code"),
    ("24_analysis_summary.png", "make analyze: summary table - secure code clean in every check"),
    ("25_ci_github_actions.png", "GitHub Actions: CI runs passing on every push"),
]


def section_15(rep):
    rep.h1("15. Screenshots / Demonstration")
    rep.para(
        "This chapter shows the program runs, test results and analysis output captured in the "
        "project's GitHub Codespace, and the continuous-integration runs on GitHub.")
    for i, (f, cap) in enumerate(SHOT_CAPTIONS, 1):
        if i == 2:
            rep.shot(f, "15.2a", cap)
            rep.figure(os.path.join(FIGS, "term_tree.png"), "15.2b",
                       "Repository tree (tree -a -L 3)")
            continue
        if i == 26:
            break
        rep.shot(f, f"15.{i}", cap)
    for k in range(1, 7):
        rep.shot(f"26_examples_test_table_{k}.png", f"15.26{'abcdef'[k - 1]}",
                 f"Twenty examples test run (part {k} of 6)")
    rep.shot("27_examples_demos.png", "15.27",
             "Examples 13 and 14: command injection and path traversal - vulnerable vs secure")


def sections_16_to_18(rep):
    rep.h1("16. Conclusion")
    rep.para(
        "The project implemented the Phase-I design end to end. The vulnerable programs showed, "
        "with real output, what unbounded string functions and unsafe formatting do: silent "
        "corruption of a privilege-relevant field, corruption of neighbouring buffers, an "
        "overwritten return address, leakage of a simulated secret, misformatted text, "
        "use-after-free, double free and crashes. The secure programs, built on a small "
        "safe-string library and the workflow Input - Validation - Length check - Safe handling - "
        "Output verification - Result, rejected every malicious or malformed input with a clear "
        f"reason. All {GRAND_TOTAL} automated tests pass with AddressSanitizer and UBSan enabled, "
        "and gcc, Cppcheck, the banned-API scanner, AddressSanitizer and Valgrind report no "
        "findings in the secure code.")
    rep.para(
        "The comparison of tools was one of the most useful results: AddressSanitizer missed the "
        "intra-struct overflow and every logic bug, Valgrind missed the stack overflows until the "
        "crash, Cppcheck missed strcpy, strcat, sprintf and printf(msg), and none of them can see "
        "missing validation. Prevention by design - bounded operations, whitelist validation, "
        "checked conversions and fixed format strings - supported by several detection layers "
        "and systematic vulnerable-vs-secure tests, is what made the secure versions reliable. "
        "All seven Phase-I objectives were met.")

    rep.h1("17. Future Enhancements")
    rep.bullets([
        "**Fuzzing** of validate_input, input_read_line and the secure programs with libFuzzer or "
        "AFL++ to find inputs the hand-written test cases do not cover.",
        "**Additional static analysers** - clang --analyze, gcc -fanalyzer and an abstract-"
        "interpretation tool in the spirit of [2] - to compare with Cppcheck.",
        "**Taint tracking** of untrusted strings to dangerous sinks, as in SaTC [4], instead of "
        "the pattern-based banned-API scan.",
        "Comparison with **C11 Annex K** (strcpy_s, strcat_s) and **strlcpy/strlcat**, and with a "
        "memory-safe language, following the cross-language patching idea of SOLDER [5].",
        "**Hardware-assisted protection** - memory tagging [1] and return-address protection [3] "
        "- as an extra layer below the source-level fixes.",
        "**UTF-8-aware validation** for international names and messages.",
        "**LLM-assisted secure code review** guided by CWE entries, as studied in [6].",
        "Test coverage measurement (gcov) and running the suite on other compilers (clang) and "
        "architectures (ARM) in CI.",
    ])

    rep.h1("18. References")
    refs = [
        "D. Schrammel, M. Unterguggenberger, L. Lamster, S. Sultana, K. Grewal, M. LeMay, D. M. Durham, and S. Mangard, “Memory tagging using cryptographic integrity on commodity x86 CPUs,” in Proc. 2024 IEEE 9th Eur. Symp. Secur. Privacy (EuroS&P), 2024, pp. 311–326, doi: 10.1109/EuroSP60621.2024.00024.",
        "X. Cheng, J. Wang, and Y. Sui, “Precise sparse abstract execution via cross-domain interaction,” in Proc. IEEE/ACM 46th Int. Conf. Softw. Eng. (ICSE), Lisbon, Portugal, Apr. 2024, pp. 1335–1346, doi: 10.1145/3597503.3639220.",
        "L. Sharma and N. Goel, “RISC-V based secure processor architecture for return address protection,” in Proc. 38th Int. Conf. VLSI Design and 24th Int. Conf. Embedded Syst. (VLSID), 2025, pp. 481–486, doi: 10.1109/VLSID64188.2025.00095.",
        "L. Chen, Y. Wang, J. Linghu, Q. Hou, Q. Cai, S. Guo, and Z. Xue, “SaTC: Shared-keyword aware taint checking for detecting bugs in embedded systems,” IEEE Trans. Dependable Secure Comput., vol. 21, no. 4, pp. 2421–2433, Jul./Aug. 2024, doi: 10.1109/TDSC.2023.3307430.",
        "R. Williams, A. Gavazzi, and E. Kirda, “SOLDER: Retrofitting legacy code with cross-language patches,” in Proc. IEEE Int. Conf. Softw. Anal., Evol. Reengineering (SANER), 2023, pp. 49–60, doi: 10.1109/SANER56733.2023.00015.",
        "J. Zhao, Y. Sun, C. Huang, C. Liu, Y. Guan, Y. Zeng, and Y. Liu, “Towards secure code generation with LLMs: A study on common weakness enumeration,” IEEE Trans. Softw. Eng., vol. 51, no. 12, pp. 3507–3523, Dec. 2025, doi: 10.1109/TSE.2025.3619281.",
        "MITRE Corporation, “Common Weakness Enumeration (CWE).” [Online]. Available: https://cwe.mitre.org/",
        "Software Engineering Institute, Carnegie Mellon University, “SEI CERT C Coding Standard.” [Online]. Available: https://wiki.sei.cmu.edu/confluence/display/c",
        "R. C. Seacord, Secure Coding in C and C++, 2nd ed. Upper Saddle River, NJ, USA: Addison-Wesley, 2013.",
        "Information Technology - Programming Languages - C, ISO/IEC 9899:2011, 2011.",
        "K. Serebryany, D. Bruening, A. Potapenko, and D. Vyukov, “AddressSanitizer: A fast address sanity checker,” in Proc. USENIX Annu. Tech. Conf. (ATC), 2012, pp. 309–318.",
        "N. Nethercote and J. Seward, “Valgrind: A framework for heavyweight dynamic binary instrumentation,” in Proc. 28th ACM SIGPLAN Conf. Program. Lang. Design Implement. (PLDI), 2007, pp. 89–100.",
        "D. Marjamäki, “Cppcheck manual.” [Online]. Available: https://cppcheck.sourceforge.io/manual.pdf",
        "Free Software Foundation, “Using the GNU Compiler Collection (GCC) - Warning options and instrumentation options.” [Online]. Available: https://gcc.gnu.org/onlinedocs/",
    ]
    for i, ref in enumerate(refs, 1):
        p = rep.d.add_paragraph(style="Report Body")
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.left_indent = Cm(1.0)
        p.paragraph_format.first_line_indent = Cm(-1.0)
        p.paragraph_format.tab_stops.add_tab_stop(Cm(1.0))
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.space_after = Pt(6)
        p.add_run(f"[{i}]\t{ref}")


def appendices(rep):
    rep.h1("Appendix A - Source Code of Q1, Q2 and safe_string.h")
    rep.para("This appendix lists the complete code of the two case studies (vulnerable and "
             "secure versions) and the interface of the safe-string library.")
    files = ["src/lib/safe_string.h", "src/vulnerable/q1_overflow.c", "src/secure/q1_overflow.c",
             "src/vulnerable/q2_format.c", "src/secure/q2_format.c"]
    for n, f in enumerate(files, 1):
        rep.h2(f"A.{n} {f}")
        rep.code(read(os.path.join(ROOT, f)).rstrip("\n").split("\n"))
    rep.para("**Full source code:** https://github.com/Anand8k7/string-vuln-prevention "
             "(input_handler, safe_string.c, the twenty examples, tests and analysis scripts).")
    rep.h1("Appendix B - Complete Test Table for the Twenty Examples")
    rep.table("B.1", f"All {len(EX)} example test cases (tests/scenarios/examples.sh)",
              ["ID", "Category", "Input", "Vulnerable (plain)", "Vulnerable (ASan)", "Expected",
               "Secure result", "Result"],
              [[r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[8]] for r in EX],
              [1.35, 1.9, 2.4, 2.4, 2.55, 1.8, 2.5, 1.3])


# =============================================================================
# Build, render, page numbers
# =============================================================================
# Child order required by the WordprocessingML schema (ECMA-376).
_TBLPR_ORDER = ["tblStyle", "tblpPr", "tblOverlap", "bidiVisual", "tblStyleRowBandSize",
                "tblStyleColBandSize", "tblW", "jc", "tblCellSpacing", "tblInd", "tblBorders",
                "shd", "tblLayout", "tblCellMar", "tblLook", "tblCaption", "tblDescription"]
_PPR_ORDER = ["pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr", "widowControl",
              "numPr", "suppressLineNumbers", "pBdr", "shd", "tabs", "suppressAutoHyphens",
              "kinsoku", "wordWrap", "overflowPunct", "topLinePunct", "autoSpaceDE", "autoSpaceDN",
              "bidi", "adjustRightInd", "snapToGrid", "spacing", "ind", "contextualSpacing",
              "mirrorIndents", "suppressOverlap", "jc", "textDirection", "textAlignment",
              "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr", "pPrChange"]
_TCPR_ORDER = ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd", "noWrap",
               "tcMar", "textDirection", "tcFitText", "vAlign", "hideMark"]


def _reorder(el, order):
    rank = {qn("w:" + n): i for i, n in enumerate(order)}
    kids = list(el)
    kids.sort(key=lambda k: rank.get(k.tag, len(order)))
    for k in kids:
        el.remove(k)
    for k in kids:
        el.append(k)


def fix_schema_order(d):
    root = d.element
    for el in root.iter(qn("w:tblPr")):
        _reorder(el, _TBLPR_ORDER)
    for el in root.iter(qn("w:pPr")):
        _reorder(el, _PPR_ORDER)
    for el in root.iter(qn("w:tcPr")):
        _reorder(el, _TCPR_ORDER)
    for el in d.styles.element.iter(qn("w:pPr")):      # e.g. the Code style's box
        _reorder(el, _PPR_ORDER)


def build(pages):
    rep = Report(pages)
    contents_p = fill_front_matter(rep)
    words = section_abstract(rep, contents_p)
    fill_contents_table(rep)
    # The List of Figures/Tables needs the captions, which are created by the
    # later sections: build those into a scratch report first.
    probe = Report({})
    fill_front_matter(probe)
    sections_4_to_8(probe); sections_9_to_11(probe); section_12(probe); section_13(probe)
    section_14(probe); section_15(probe); sections_16_to_18(probe); appendices(probe)
    section_lof(rep, probe.figures, probe.tables)
    sections_4_to_8(rep); sections_9_to_11(rep); section_12(rep); section_13(rep)
    section_14(rep); section_15(rep); sections_16_to_18(rep); appendices(rep)
    fix_schema_order(rep.d)
    rep.d.save(OUT_DOCX)
    subprocess.run(["zip", "-q", "-d", OUT_DOCX, "*/"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    return rep, words


def render():
    subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "--outdir", HERE, OUT_DOCX],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    txt = subprocess.run(["pdftotext", "-layout", OUT_PDF, "-"], capture_output=True,
                         text=True, check=True).stdout
    return [" ".join(p.split()) for p in txt.split("\f")]


HEAD_KEYS = {
    "abstract": "1. Abstract", "lof": "3. List of Figures and Tables",
    "s4": "4. Introduction", "s5": "5. Problem Statement", "s6": "6. Objectives",
    "s7": "7. Literature Review / Existing System", "s8": "8. Proposed System",
    "s9": "9. System Architecture / Workflow", "s10": "10. Tools and Technologies Used",
    "s11": "11. Methodology", "s12": "12. Implementation / Project Development",
    "s13": "13. Experimental Setup", "s14": "14. Results and Analysis",
    "s15": "15. Screenshots / Demonstration", "s16": "16. Conclusion",
    "s17": "17. Future Enhancements", "s18": "18. References",
    "appA": "Appendix A - Source Code of Q1, Q2 and safe_string.h",
    "appB": "Appendix B - Complete Test Table for the Twenty Examples",
}


def find_pages(pages_text, rep):
    found = {}
    contents_pg = next(i for i, t in enumerate(pages_text) if "2. Table of Contents SI No" in t) + 1
    found["contents"] = contents_pg
    found["abstract"] = next(i for i, t in enumerate(pages_text) if HEAD_KEYS["abstract"] in t) + 1
    start = contents_pg
    for key, head in HEAD_KEYS.items():
        if key == "abstract":
            continue
        for i in range(start, len(pages_text)):
            if head in pages_text[i]:
                found[key] = i + 1
                break
        else:
            raise SystemExit(f"heading not found in PDF: {head}")
    body_start = found["s4"] - 1
    for kind, items in (("F", rep.figures), ("T", rep.tables)):
        word = "Figure" if kind == "F" else "Table"
        for label, _ in items:
            needle = f"{word} {label}:"
            for i in range(body_start, len(pages_text)):
                if needle in pages_text[i]:
                    found[kind + label] = i + 1
                    break
            else:
                raise SystemExit(f"caption not found in PDF: {needle}")
    return found


def main():
    for f in [TEMPLATE] + [os.path.join(SHOTS, s) for s, _ in SHOT_CAPTIONS]:
        if not os.path.exists(f):
            sys.exit(f"missing input: {f}")
    pages = {}
    for attempt in range(1, 5):
        rep, words = build(pages)
        text = render()
        new = find_pages(text, rep)
        print(f"pass {attempt}: {len(text) - 1} pages, abstract {words} words")
        if new == pages:
            break
        pages = new
    else:
        sys.exit("page numbers did not settle")
    sparse = []
    for i, t in enumerate(text[:-1], 1):
        words = len(t.split())
        if words < 90:
            sparse.append((i, words))
    print("pages with little text (page, words):", sparse)
    print("contents:", {k: pages[k] for k in ["abstract", "contents", "lof"] + [f"s{i}" for i in range(4, 19)]})
    print("written:", OUT_DOCX, OUT_PDF)


if __name__ == "__main__":
    main()
