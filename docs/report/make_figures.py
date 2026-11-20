#!/usr/bin/env python3
"""
make_figures.py - Draw the diagrams and "captured terminal output" images
used by build_final_report.py.

CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities

Output (docs/report/figures/):
  workflow.png        prevention workflow (6 stages + reject path)
  architecture.png    modules, files and build/test/analysis pipeline
  term_tree.png       full repository tree, rendered from a real run of
                      `tree` (captured terminal output)
"""
import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)

SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

INK = (33, 37, 41)
BLUE = (31, 78, 140)
BLUE_BG = (226, 236, 248)
GREEN = (36, 120, 64)
GREEN_BG = (226, 243, 231)
RED = (170, 40, 40)
RED_BG = (250, 228, 228)
GREY_BG = (243, 244, 246)
GREY = (110, 115, 122)


def font(path, size):
    return ImageFont.truetype(path, size)


def box(d, xy, fill, outline, lines, f_title, f_body, title_color=INK):
    x0, y0, x1, y1 = xy
    d.rounded_rectangle(xy, radius=14, fill=fill, outline=outline, width=3)
    total = 0
    sizes = []
    for i, t in enumerate(lines):
        f = f_title if i == 0 else f_body
        bb = d.textbbox((0, 0), t, font=f)
        sizes.append((bb[2] - bb[0], bb[3] - bb[1], f))
        total += bb[3] - bb[1] + (10 if i == 0 else 6)
    y = y0 + (y1 - y0 - total) / 2
    for i, (t, (w, h, f)) in enumerate(zip(lines, sizes)):
        d.text((x0 + (x1 - x0 - w) / 2, y), t, font=f,
               fill=title_color if i == 0 else INK)
        y += h + (10 if i == 0 else 6)


def arrow(d, p0, p1, color=INK, width=4, head=14):
    d.line([p0, p1], fill=color, width=width)
    import math
    ang = math.atan2(p1[1] - p0[1], p1[0] - p0[0])
    a1 = (p1[0] - head * math.cos(ang - 0.45), p1[1] - head * math.sin(ang - 0.45))
    a2 = (p1[0] - head * math.cos(ang + 0.45), p1[1] - head * math.sin(ang + 0.45))
    d.polygon([p1, a1, a2], fill=color)


def workflow():
    W, H = 2000, 900
    im = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(im)
    ft, fb, fs = font(SANS_B, 30), font(SANS, 22), font(SANS, 21)
    d.text((60, 30), "Prevention workflow implemented by every secure program",
           font=font(SANS_B, 34), fill=BLUE)
    stages = [
        ("1. User Input", "input_read_line()", "input_from_arg()", "bounded fgets / argv"),
        ("2. Input Validation", "validate_input()", "validate_integer()", "whitelist, format, range"),
        ("3. Length & Boundary", "IN_TOO_LONG", "SS_TRUNCATED", "=> reject"),
        ("4. Safe String Ops", "safe_copy()", "safe_concat()", "safe_format()"),
        ("5. Output Verification", "buffers terminated", "neighbour data intact", "(e.g. role == \"guest\")"),
        ("6. Result", "fixed format strings", "printf(\"%s\", msg)", "exit code 0"),
    ]
    bw, bh, gap, top = 290, 250, 36, 140
    x = 60
    centers = []
    for i, s in enumerate(stages):
        fill, out = (GREEN_BG, GREEN) if i == 5 else (BLUE_BG, BLUE)
        size = 30
        while d.textbbox((0, 0), s[0], font=font(SANS_B, size))[2] > bw - 24:
            size -= 1
        box(d, (x, top, x + bw, top + bh), fill, out, list(s), font(SANS_B, size), fb,
            title_color=GREEN if i == 5 else BLUE)
        centers.append(x + bw / 2)
        if i < 5:
            arrow(d, (x + bw + 4, top + bh / 2), (x + bw + gap - 4, top + bh / 2))
        x += bw + gap
    # reject path
    ry0, ry1 = 560, 700
    rx0, rx1 = 60 + bw + gap, 60 + 4 * (bw + gap) + bw
    box(d, (rx0, ry0, rx1, ry1), RED_BG, RED,
        ["REJECTED: <reason>   (exit code 2)",
         "nothing is copied, formatted or printed from the bad input"],
        font(SANS_B, 28), fs, title_color=RED)
    for i in (1, 2, 3, 4):
        cx = centers[i]
        d.line([(cx, top + bh + 4), (cx, ry0 - 18)], fill=RED, width=3)
        arrow(d, (cx, ry0 - 40), (cx, ry0 - 4), color=RED, width=3, head=12)
        d.text((cx + 8, top + bh + 30), "fail", font=fs, fill=RED)
    d.text((60, 760), "Used by src/secure/q1_overflow.c, src/secure/q2_format.c and the 20 src/examples/*/secure.c programs.",
           font=fs, fill=GREY)
    d.text((60, 800), "Library: src/lib/safe_string.c, src/lib/input_handler.c  -  every status code is checked; any status other than OK is a rejection.",
           font=fs, fill=GREY)
    im.save(os.path.join(OUT, "workflow.png"))


def architecture():
    W, H = 2000, 1250
    im = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(im)
    ft, fb = font(SANS_B, 27), font(SANS, 21)
    d.text((60, 30), "Module architecture and build / test / analysis pipeline",
           font=font(SANS_B, 34), fill=BLUE)
    # row 1: sources
    srcs = [
        ("src/vulnerable/", "q1_overflow.c, q2_format.c", "deliberately unsafe"),
        ("src/secure/", "q1_overflow.c, q2_format.c", "fixed versions"),
        ("src/examples/", "20 x vulnerable.c + secure.c", "eNN_name/"),
    ]
    y0, y1 = 120, 300
    xs = [60, 700, 1340]
    for (t, a, b), x in zip(srcs, xs):
        box(d, (x, y0, x + 600, y1), GREY_BG, GREY, [t, a, b], ft, fb)
    # library (to the right of the secure -> Makefile arrow)
    box(d, (820, 370, 1300, 600), BLUE_BG, BLUE,
        ["src/lib/ (modules 1-3)", "input_handler: bounded input", "safe_string: validate_input,",
         "validate_integer, safe_copy,", "safe_concat, safe_format"], font(SANS_B, 25), fb,
        title_color=BLUE)
    arrow(d, (1060, 370), (1060, 304), color=BLUE)
    arrow(d, (1300, 485), (1530, 304), color=BLUE)
    d.text((1330, 520), "linked by every", font=fb, fill=BLUE)
    d.text((1330, 548), "secure program", font=fb, fill=BLUE)
    # builds
    box(d, (60, 680, 1940, 820), GREY_BG, GREY,
        ["Makefile builds 4 variants of every program",
         "vulnerable (-O0, no protections)  |  secure (-Werror, FORTIFY, stack protector, PIE, RELRO)  |  "
         "vulnerable+ASan  |  secure+ASan (-fsanitize=address,undefined)"], ft, fb)
    for x in (360, 760, 1640):
        arrow(d, (x, 304), (x, 676))
    # bottom: testing + analysis + CI
    boxes = [
        ("Module 5: Testing", "make test: 213 tests", "unit tests (80) + scenarios", "Q1 17, Q2 26, examples 90"),
        ("Module 4: Analysis", "make analyze", "gcc warnings, cppcheck,", "banned-API scan, ASan, Valgrind"),
        ("CI (GitHub Actions)", ".github/workflows/ci.yml", "build + test + gates on", "secure code, every push"),
    ]
    for (t, a, b, c), x in zip(boxes, xs):
        box(d, (x, 920, x + 600, 1120), GREEN_BG, GREEN, [t, a, b, c], ft, fb, title_color=GREEN)
        arrow(d, (x + 300, 824), (x + 300, 916), color=GREEN)
    d.text((60, 1160), "Results are saved in analysis/logs/ and docs/report/outputs/; every number in this report comes from those files.",
           font=font(SANS, 21), fill=GREY)
    im.save(os.path.join(OUT, "architecture.png"))


def terminal(name, prompt_cmd, text, max_lines=None):
    """Render real command output like a dark terminal (captured output)."""
    lines = text.rstrip("\n").split("\n")
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more lines)"]
    f = font(MONO, 18)
    lh = 24
    width = max([len(prompt_cmd) + 2] + [len(l) for l in lines]) * 11 + 60
    height = (len(lines) + 2) * lh + 40
    im = Image.new("RGB", (max(width, 700), height), (30, 30, 30))
    d = ImageDraw.Draw(im)
    d.text((20, 15), "$ ", font=f, fill=(110, 200, 120))
    d.text((44, 15), prompt_cmd, font=f, fill=(230, 230, 230))
    y = 15 + lh + 6
    for l in lines:
        d.text((20, y), l, font=f, fill=(212, 212, 212))
        y += lh
    im.save(os.path.join(OUT, name))


def term_tree():
    cmd = "tree -a -L 3 -I '.git|bin|unused|outputs|figures|logs' --dirsfirst"
    txt = subprocess.run(["bash", "-c", cmd], cwd=ROOT, capture_output=True,
                         text=True).stdout
    terminal("term_tree.png", cmd, txt)
    return cmd


if __name__ == "__main__":
    workflow()
    architecture()
    term_tree()
    print("figures written to", OUT)
