"""
scanner.py - rule-based static scanner for string vulnerabilities in C/C++.

It is deliberately simple: comments are blanked out (line numbers kept),
calls are found with a regex, and their arguments are split by a small
parser that understands nested brackets, string and character literals.
It is a teaching aid that points at risky patterns, not a full analyser,
so the results are combined with cppcheck in the web app.
"""
import re

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}

# Explanations and safe replacements, one entry per rule.
RULES = {
    "gets": dict(
        title="gets() has no length limit", cwe="CWE-242", severity="critical",
        explain="gets() reads a whole line into the buffer without knowing its size, "
                "so any line longer than the buffer overflows it. It was removed from C11.",
        fix='fgets(buf, sizeof buf, stdin); then remove the trailing "\\n" '
            '(project: input_read_line(stdin, buf, sizeof buf, &len)).'),
    "strcpy": dict(
        title="strcpy() does not check the destination size", cwe="CWE-120", severity="high",
        explain="strcpy() copies until the source's '\\0'. If the source is longer than "
                "the destination, the bytes after the buffer are overwritten.",
        fix="snprintf(dst, sizeof dst, \"%s\", src) and check the return value "
            "(project: safe_copy(dst, sizeof dst, src) and reject SS_TRUNCATED)."),
    "strcat": dict(
        title="strcat() does not check the remaining space", cwe="CWE-120", severity="high",
        explain="strcat() appends without knowing how much room is left in the "
                "destination, so long input writes past its end.",
        fix="Check strlen(dst) + strlen(src) < sizeof dst first, or use "
            "safe_concat(dst, sizeof dst, src) and reject SS_TRUNCATED."),
    "sprintf": dict(
        title="sprintf() output size is unbounded", cwe="CWE-787", severity="high",
        explain="sprintf() writes the whole formatted result, however long, into the "
                "buffer. Long %s arguments overflow it.",
        fix="snprintf(buf, sizeof buf, fmt, ...) and treat a return value >= sizeof buf "
            "as truncation (project: safe_format)."),
    "vsprintf": dict(
        title="vsprintf() output size is unbounded", cwe="CWE-787", severity="high",
        explain="vsprintf() is sprintf() with a va_list and has the same overflow problem.",
        fix="vsnprintf(buf, sizeof buf, fmt, ap) and check the return value."),
    "scanf_s": dict(
        title="%s / %[ in scanf without a field width", cwe="CWE-120", severity="high",
        explain="Without a width, %s keeps writing characters until whitespace, so a "
                "long word overflows the destination buffer.",
        fix='Give a width one less than the buffer: scanf("%15s", buf) for char buf[16], '
            "and check the return value; or read the line with fgets()."),
    "format": dict(
        title="Format string is not a literal", cwe="CWE-134", severity="high",
        explain="When user data is the format string, directives such as %p, %x or %n "
                "inside it are interpreted: stack values are printed, memory can be written.",
        fix='Always use a fixed format: printf("%s", msg) instead of printf(msg).'),
    "strncpy": dict(
        title="strncpy() result may not be '\\0'-terminated", cwe="CWE-170", severity="medium",
        explain="If the source is at least n bytes long, strncpy() copies n bytes and does "
                "not add '\\0'. Later string functions then read past the buffer.",
        fix="Terminate explicitly: dst[sizeof dst - 1] = '\\0'; or use safe_copy / "
            "snprintf, which always terminate and report truncation."),
    "memcpy_strlen": dict(
        title="memcpy() size taken from strlen()", cwe="CWE-131", severity="high",
        explain="The size comes from the source, not from the destination. A long "
                "source overflows the destination, and strlen() leaves out the '\\0'.",
        fix="Check len < sizeof dst first, copy len + 1 bytes (or add '\\0'), or use safe_copy."),
    "memcpy_sizeof_src": dict(
        title="memcpy() size taken from the source buffer", cwe="CWE-131", severity="high",
        explain="sizeof applied to the SOURCE says how big the source is, not how much room "
                "the destination has. If the source is bigger, the destination overflows.",
        fix="Use the destination size and check it: if (len >= sizeof dst) reject; "
            "memcpy(dst, src, len); dst[len] = '\\0';  (or safe_copy)."),
    "use_after_free": dict(
        title="Pointer used after free()", cwe="CWE-416", severity="high",
        explain="After free(p) the memory may be reused for something else; reading or "
                "writing through p gives wrong data or corrupts the heap.",
        fix="Use the data first, then free once and set p = NULL. Do not touch p after free()."),
    "double_free": dict(
        title="Pointer freed twice", cwe="CWE-415", severity="high",
        explain="Calling free() twice on the same block corrupts the allocator's data and "
                "can be exploited.",
        fix="Free each block exactly once from a single clean-up point and set it to NULL "
            "right after free()."),
    "system": dict(
        title="Command executed through the shell", cwe="CWE-78", severity="high",
        explain="system()/popen() pass the string to /bin/sh. If any part of it comes from "
                "the user, characters like ; | && $( ) run extra commands.",
        fix="Avoid the shell: use fork()+execv() with an argument array, and whitelist the "
            "input (letters/digits only) before using it."),
    "system_literal": dict(
        title="Command executed through the shell (fixed string)", cwe="CWE-78", severity="low",
        explain="The command is a fixed string, so it is not injectable, but system() still "
                "depends on PATH and the shell environment.",
        fix="Prefer execv() with a full path, or library calls instead of shell commands."),
    "off_by_one": dict(
        title="Loop bound uses <= (possible off-by-one)", cwe="CWE-193", severity="medium",
        explain="A loop that runs while i <= size touches index size, one past the last "
                "valid element (valid indexes are 0 .. size-1).",
        fix="Use i < size (and keep one byte for '\\0' when building strings)."),
    "malloc_strlen": dict(
        title="malloc(strlen(s)) leaves no room for '\\0'", cwe="CWE-131", severity="high",
        explain="strlen() does not count the terminating '\\0', so copying the string "
                "into this block writes one byte past the allocation.",
        fix="malloc(strlen(s) + 1), check for NULL, then copy with safe_copy/memcpy(len + 1)."),
    "unchecked_alloc": dict(
        title="Allocation result not checked for NULL", cwe="CWE-252", severity="medium",
        explain="malloc/calloc/realloc return NULL when they fail. Using the pointer "
                "without a check crashes (NULL dereference, CWE-476).",
        fix="if (p == NULL) { handle the error; } right after the call."),
    "unchecked_scanf": dict(
        title="scanf() return value ignored", cwe="CWE-252", severity="medium",
        explain="scanf() returns how many fields it converted. When it is ignored, bad "
                "input (e.g. 'abc' for %d) leaves variables uninitialised.",
        fix="if (scanf(\"%d\", &n) != 1) { reject; } or read a line and parse it "
            "with strtol() (project: validate_integer)."),
    "atoi": dict(
        title="atoi() cannot report errors", cwe="CWE-190", severity="low",
        explain="atoi() returns 0 for non-numbers and has undefined behaviour on overflow, "
                "so invalid input cannot be told apart from 0.",
        fix="strtol() with errno and end-pointer checks, plus a range check "
            "(project: validate_integer)."),
    "strtok": dict(
        title="strtok() is not reentrant", cwe="CWE-663", severity="low",
        explain="strtok() keeps hidden state; a nested or concurrent call loses the "
                "position of the outer loop.",
        fix="strtok_r(str, delim, &saveptr)."),
}

CALL_RE = re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf|scanf|fscanf|sscanf|"
                     r"printf|fprintf|snprintf|syslog|strncpy|memcpy|memmove|system|popen|"
                     r"malloc|calloc|realloc|atoi|atol|strtok)\s*\(")
# Format argument position (0-based) for format-string checks.
FORMAT_ARG = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}


def strip_comments(code):
    """Replace comments with spaces (newlines kept) so offsets and line
    numbers stay the same. String/char literals are left untouched."""
    out = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c == "/" and i + 1 < n and code[i + 1] == "/":
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and i + 1 < n and code[i + 1] == "*":
            j = code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", code[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and code[j] != c and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(code[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def split_args(text, open_pos):
    """text[open_pos] is '('. Returns (list of argument strings, end index)."""
    depth, i, n = 0, open_pos, len(text)
    args, cur = [], []
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return (args if args != [""] else []), i
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    args.append("".join(cur).strip())
    return args, n


def first_literal(arg):
    """Concatenated content of the string literal(s) in arg, or None."""
    parts = re.findall(r'"((?:[^"\\\n]|\\.)*)"', arg)
    return "".join(parts) if parts and arg.lstrip().startswith(('"', "L\"", "u8\"")) else None


def _skip_statement(text, pos):
    """Index just after the statement or {block} that starts at pos."""
    m = re.compile(r"\s*").match(text, pos)
    pos = m.end()
    if pos < len(text) and text[pos] == "{":
        depth = 0
        for i in range(pos, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        return len(text)
    j = text.find(";", pos)
    return len(text) if j == -1 else j + 1


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def statement_start(text, pos):
    """True if the call at pos starts a statement (its value is unused)."""
    j = pos - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    if j < 0 or text[j] in ";{}":
        return True
    # "(void)scanf(...)" explicitly discards the value - treat as unchecked
    return text[max(0, j - 5):j + 1] == "(void)"


def scan(code):
    text = strip_comments(code)
    lines = code.split("\n")
    findings = []

    def add(rule, pos, detail=""):
        r = RULES[rule]
        ln = line_of(text, pos)
        findings.append({
            "rule": rule, "line": ln, "cwe": r["cwe"], "severity": r["severity"],
            "title": r["title"], "explain": r["explain"], "fix": r["fix"],
            "detail": detail,
            "code": lines[ln - 1].strip() if ln - 1 < len(lines) else "",
            "source": "rules",
        })

    for m in CALL_RE.finditer(text):
        name = m.group(1)
        pos = m.start()
        # skip declarations/definitions such as "char *gets(char *);"
        before = text[max(0, pos - 40):pos]
        if re.search(r"(\bchar\s*\*|\bint|\bvoid\s*\*|\bvoid)\s*$", before):
            continue
        # skip member access like obj.printf( / ptr->strcpy(
        if re.search(r"(\.|->)\s*$", before):
            continue
        args, end = split_args(text, m.end() - 1)

        if name in ("gets", "strcpy", "strcat", "sprintf", "vsprintf"):
            add(name, pos)

        if name in ("scanf", "fscanf", "sscanf"):
            fi = 0 if name == "scanf" else 1
            fmt = first_literal(args[fi]) if len(args) > fi else None
            if fmt is not None:
                bad = re.findall(r"%(\*?)(?:[hlLqjzt]*)(s|\[)", fmt)
                if bad:
                    add("scanf_s", pos, f'format "{fmt}"')
            if statement_start(text, pos):
                add("unchecked_scanf", pos)

        if name in FORMAT_ARG:
            fi = FORMAT_ARG[name]
            if len(args) > fi and first_literal(args[fi]) is None:
                arg = args[fi]
                # common safe forms: a const macro in CAPS is still reported,
                # but with lower confidence
                detail = f"format argument is `{arg}`"
                add("format", pos, detail)

        if name == "strncpy" and args:
            dst = re.escape(args[0])
            window = text[end:end + 400]
            terminated = re.search(dst + r"\s*\[[^\]]*\]\s*=\s*('\\0'|0)\s*;", window)
            if not terminated:
                add("strncpy", pos, f"destination `{args[0]}` is not terminated afterwards")

        if name in ("memcpy", "memmove") and len(args) >= 3 and "strlen" in args[2]:
            add("memcpy_strlen", pos, f"size argument is `{args[2]}`")

        if name in ("memcpy", "memmove") and len(args) >= 3:
            sm = re.fullmatch(r"sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?", args[2])
            if sm and sm.group(1) == args[1].strip() and sm.group(1) != args[0].strip():
                add("memcpy_sizeof_src", pos, f"size is `{args[2]}`, the destination is `{args[0]}`")

        if name in ("system", "popen") and args:
            if first_literal(args[0]) is not None and "+" not in args[0]:
                add("system_literal", pos)
            else:
                add("system", pos, f"command is `{args[0]}`")

        if name == "malloc" and args and "strlen" in args[0] and not re.search(r"\+\s*1\b", args[0]):
            add("malloc_strlen", pos, f"size is `{args[0]}`")

        if name in ("malloc", "calloc", "realloc"):
            # p = malloc(...);  ->  look for a NULL check of p
            am = re.search(r"([A-Za-z_][\w\.\->\[\]]*)\s*=\s*(\([^()]*\)\s*)?$",
                           text[max(0, pos - 120):pos])
            if am:
                var = am.group(1).split()[-1]
                window = text[end:end + 600]
                v = re.escape(var)
                checked = re.search(
                    rf"(!\s*{v}\b|\b{v}\s*[!=]=\s*(NULL|0|nullptr)\b|\b(NULL|nullptr)\s*[!=]=\s*{v}\b|"
                    rf"if\s*\(\s*{v}\s*\)|assert\s*\(\s*{v})", window)
                if not checked:
                    add("unchecked_alloc", pos, f"`{var}` is used without a NULL check")
            elif statement_start(text, pos):
                add("unchecked_alloc", pos, "result is not stored")

        if name in ("atoi", "atol"):
            add("atoi", pos)
        if name == "strtok":
            add("strtok", pos)

    # Use after free / double free: after free(p), the next mention of p
    # (before p is reassigned) is reported. Skipped when control flow leaves
    # the block first (return/goto/break/continue/exit), which is the usual
    # error-path pattern.
    # References are searched in a copy with string contents blanked, so a
    # word inside "..." is not mistaken for the variable.
    code_only = re.sub(r'"(?:[^"\\\n]|\\.)*"', lambda q: '"' + " " * (len(q.group(0)) - 2) + '"', text)
    for m in re.finditer(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;", code_only):
        var = m.group(1)
        v = re.escape(var)
        cursor, limit = m.end(), min(len(code_only), m.end() + 800)
        # stop at the end of the enclosing function (brace depth back to 0)
        depth = code_only.count("{", 0, m.start()) - code_only.count("}", 0, m.start())
        for i in range(m.end(), limit):
            ch = code_only[i]
            depth += (ch == "{") - (ch == "}")
            if depth <= 0:
                limit = i
                break
        while cursor < limit:
            ref = re.compile(rf"\b{v}\b").search(code_only, cursor, limit)
            if not ref:
                break
            seg = code_only[cursor:ref.start()]
            e = re.search(r"\belse\b", seg)
            if e:
                # the else branch cannot run after a free() in the if branch
                cursor = _skip_statement(code_only, cursor + e.end())
                continue
            # a return inside a nested { } block does not leave this path
            flat = seg
            while True:
                reduced = re.sub(r"\{[^{}]*\}", " ", flat)
                if reduced == flat:
                    break
                flat = reduced
            if re.search(r"\b(return|goto|break|continue|exit|abort)\b", flat):
                break
            if re.match(rf"{v}\s*=[^=]", code_only[ref.start():]):   # p = NULL / new value
                break
            first = line_of(text, m.start())
            if re.search(r"\bfree\s*\(\s*$", code_only[:ref.start()]):
                add("double_free", ref.start(), f"`{var}` was already freed on line {first}")
            else:
                add("use_after_free", ref.start(), f"`{var}` was freed on line {first}")
            break

    # Off-by-one: for (...; i <= BOUND; ...) where BOUND looks like a size.
    for m in re.finditer(r"\bfor\s*\(", text):
        _, close = split_args(text, m.end() - 1)
        parts = text[m.end():close].split(";")
        if len(parts) >= 2:
            cond = parts[1].strip()
            cm = re.search(r"\b\w+\s*<=\s*(.+)$", cond)
            if cm:
                bound = cm.group(1)
                if re.search(r"sizeof|strlen|\blen\b|\blength\b|\bsize\b|\bcount\b|"
                             r"\b[A-Z][A-Z0-9_]{1,}\b|\b\d+\b", bound):
                    add("off_by_one", m.start(), f"condition `{cond}`")

    findings.sort(key=lambda f: (f["line"], -SEVERITY_WEIGHT[f["severity"]]))
    return findings


def score(findings):
    """100 = no findings. Each finding subtracts its weight (floored at 0)."""
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 3) for f in findings)
    value = max(0, 100 - penalty)
    if value >= 90:
        grade = "A"
    elif value >= 75:
        grade = "B"
    elif value >= 50:
        grade = "C"
    elif value >= 25:
        grade = "D"
    else:
        grade = "F"
    counts = {k: 0 for k in SEVERITY_WEIGHT}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"score": value, "grade": grade, "counts": counts, "total": len(findings)}
