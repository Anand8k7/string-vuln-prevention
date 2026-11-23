"""
asan_explain.py - turn AddressSanitizer / UBSan / LeakSanitizer output into
short plain-English explanations (type of bug, line, variable, bytes).
"""
import re

KINDS = {
    "stack-buffer-overflow": ("Stack buffer overflow", "CWE-121",
        "The program wrote or read past the end of a local array on the stack."),
    "stack-buffer-underflow": ("Stack buffer underflow", "CWE-124",
        "The program accessed memory just before the start of a local array."),
    "heap-buffer-overflow": ("Heap buffer overflow", "CWE-122",
        "The program accessed memory past the end of a block returned by malloc/new."),
    "global-buffer-overflow": ("Global buffer overflow", "CWE-787",
        "The program accessed memory past the end of a global or static array."),
    "heap-use-after-free": ("Use after free", "CWE-416",
        "The program used heap memory after it had already been freed."),
    "double-free": ("Double free", "CWE-415",
        "The same heap block was passed to free() twice."),
    "attempting double-free": ("Double free", "CWE-415",
        "The same heap block was passed to free() twice."),
    "bad-free": ("Invalid free", "CWE-590",
        "free() was called on a pointer that was not returned by malloc."),
    "stack-use-after-return": ("Stack use after return", "CWE-562",
        "The program used a pointer to a local variable after its function returned."),
    "stack-use-after-scope": ("Stack use after scope", "CWE-562",
        "The program used a local variable after the block that declared it ended."),
    "dynamic-stack-buffer-overflow": ("Dynamic stack buffer overflow", "CWE-121",
        "The program accessed past the end of a variable-length (alloca/VLA) array."),
    "SEGV": ("Segmentation fault", "CWE-476",
        "The program accessed an invalid address (often a NULL or wild pointer)."),
    "stack-overflow": ("Stack overflow (recursion)", "CWE-674",
        "The call stack ran out of space, usually because of unbounded recursion."),
    "allocation-size-too-big": ("Allocation too big", "CWE-789",
        "malloc was asked for an enormous size (often a negative or wrapped length)."),
    "negative-size-param": ("Negative size", "CWE-195",
        "A memory function received a negative size (signed/unsigned mix-up)."),
    "memcpy-param-overlap": ("Overlapping memcpy", "CWE-475",
        "memcpy/strcpy source and destination overlap; the result is undefined."),
    "strcpy-param-overlap": ("Overlapping strcpy", "CWE-475",
        "strcpy source and destination overlap; the result is undefined."),
    "strcat-param-overlap": ("Overlapping strcat", "CWE-475",
        "strcat source and destination overlap; the result is undefined."),
    "alloc-dealloc-mismatch": ("Allocator mismatch", "CWE-762",
        "Memory was freed with a function that does not match how it was allocated."),
    "calloc-overflow": ("calloc size overflow", "CWE-190",
        "count * size in calloc overflowed."),
    "out-of-memory": ("Out of memory", "CWE-789",
        "The program tried to use more memory than the sandbox allows."),
    "rss-limit-exceeded": ("Memory limit exceeded", "CWE-400",
        "The program used more memory than the sandbox allows (256 MB)."),
}

FRAME_RE = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)")


def _user_frame(block, src_names):
    """First stack frame that points into the user's source file."""
    for m in FRAME_RE.finditer(block):
        func, path, line = m.groups()
        if path.rsplit("/", 1)[-1] in src_names:
            return {"function": func, "file": path.rsplit("/", 1)[-1], "line": int(line)}
    return None


def explain(output, src_names=("main.c", "main.cpp")):
    """Return a list of findings explained in plain English."""
    results = []

    # ---- AddressSanitizer ------------------------------------------------
    for m in re.finditer(r"ERROR: AddressSanitizer: (.+)", output):
        head = m.group(1)
        start = m.start()
        nxt = output.find("==ERROR:", m.end())
        block = output[start: nxt if nxt != -1 else len(output)]
        kind = head.split(" on ")[0].split(" ")[0].strip()
        if head.startswith("attempting double-free"):
            kind = "double-free"
        elif head.startswith("attempting free on address which was not malloc"):
            kind = "bad-free"
        elif head.startswith("requested allocation size"):
            kind = "allocation-size-too-big"
        title, cwe, desc = KINDS.get(kind, (kind, "", "AddressSanitizer reported a memory error."))
        r = {"tool": "AddressSanitizer", "kind": kind, "title": title, "cwe": cwe,
             "description": desc}

        acc = re.search(r"(READ|WRITE) of size (\d+)", block)
        if acc:
            r["access"] = acc.group(1).lower()
            r["bytes"] = int(acc.group(2))

        # The first part of the report (before "allocated by" / "freed by")
        main_part = re.split(r"\n(?:allocated|freed|previously allocated) by thread", block)[0]
        r["location"] = _user_frame(main_part, src_names)

        # Stack objects of the frame. ASan reports the offset of the first bad
        # byte; the overflowed variable is the one containing that offset, or
        # else the one that ends closest before it. (The "<==" marker can
        # point at the *next* variable: "partially underflows this variable".)
        objs = [(int(lo), int(hi), name, decl) for lo, hi, name, decl in re.findall(
            r"\[(\d+), (\d+)\) '([^']+)'(?: \(line (\d+)\))?", block)]
        off = re.search(r"is located in stack of thread \w+ at offset (\d+)", block)
        pick = None
        if objs and off:
            o = int(off.group(1))
            inside = [x for x in objs if x[0] <= o < x[1]]
            before = [x for x in objs if x[1] <= o]
            if before and (not inside or "underflows" in block):
                pick = max(before, key=lambda x: x[1])
            elif inside:
                pick = inside[0]
        if pick is None:
            m = re.search(r"\[(\d+), (\d+)\) '([^']+)'(?: \(line (\d+)\))? <== Memory access", block)
            if m:
                pick = (int(m.group(1)), int(m.group(2)), m.group(3), m.group(4))
        if pick:
            lo, hi, name, decl = pick
            r["variable"] = name
            r["variable_size"] = hi - lo
            if decl:
                r["declared_line"] = int(decl)
        reg = re.search(r"is located (\d+) bytes (after|before|inside of) (\d+)-byte region", block)
        if reg:
            r["offset"] = int(reg.group(1))
            r["relation"] = reg.group(2)
            r["variable_size"] = int(reg.group(3))
        g = re.search(r"is located (\d+) bytes (after|before) global variable '([^']+)'.*?of size (\d+)", block)
        if g:
            r["relation"] = g.group(2)
            r["variable"] = g.group(3)
            r["variable_size"] = int(g.group(4))

        alloc = re.search(r"allocated by thread \w+ here:\n((?:\s+#.*\n?)+)", block)
        if alloc:
            r["allocated_at"] = _user_frame(alloc.group(1), src_names)
        freed = re.search(r"freed by thread \w+ here:\n((?:\s+#.*\n?)+)", block)
        if freed:
            r["freed_at"] = _user_frame(freed.group(1), src_names)

        r["plain"] = _sentence(r)
        results.append(r)

    # ---- LeakSanitizer ---------------------------------------------------
    for m in re.finditer(r"(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:\n((?:\s+#.*\n?)+)", output):
        loc = _user_frame(m.group(4), src_names)
        r = {"tool": "LeakSanitizer", "kind": "memory-leak", "title": "Memory leak",
             "cwe": "CWE-401", "bytes": int(m.group(2)), "location": loc,
             "description": "Memory was allocated but never freed."}
        where = f" allocated at line {loc['line']}" if loc else ""
        r["plain"] = (f"{m.group(1)} leak: {m.group(2)} byte(s) in {m.group(3)} object(s){where} "
                      "were never freed. Call free() once on every path when the memory is no longer needed.")
        results.append(r)

    # ---- UndefinedBehaviorSanitizer --------------------------------------
    for m in re.finditer(r"(\S+?):(\d+):(\d+): runtime error: (.+)", output):
        path, line, col, msg = m.groups()
        fname = path.rsplit("/", 1)[-1]
        r = {"tool": "UBSan", "kind": "undefined-behaviour", "title": "Undefined behaviour",
             "cwe": _ub_cwe(msg), "description": msg,
             "location": {"file": fname, "line": int(line), "function": ""}}
        r["plain"] = f"Line {line}: {msg}. The C standard does not define what happens here, so the result cannot be trusted."
        results.append(r)
    return results


def _ub_cwe(msg):
    if "overflow" in msg and "integer" in msg:
        return "CWE-190"
    if "index" in msg and "out of bounds" in msg:
        return "CWE-129"
    if "null pointer" in msg:
        return "CWE-476"
    if "shift" in msg:
        return "CWE-1335"
    return ""


def _b(n):
    return f"{n} byte" if n == 1 else f"{n} bytes"


def _sentence(r):
    parts = []
    loc = r.get("location")
    where = f"at line {loc['line']} (in {loc['function']})" if loc else "in a library function"
    if r["kind"] in ("stack-buffer-overflow", "heap-buffer-overflow", "global-buffer-overflow",
                     "stack-buffer-underflow", "dynamic-stack-buffer-overflow"):
        verb = {"write": "wrote", "read": "read"}.get(r.get("access"), "accessed")
        n = r.get("bytes")
        target = f"'{r['variable']}'" if r.get("variable") else "a buffer"
        size = f" ({_b(r['variable_size'])})" if r.get("variable_size") is not None else ""
        decl = f", declared at line {r['declared_line']}" if r.get("declared_line") else ""
        cap = r.get("variable_size")
        if n and cap is not None and n > cap:
            prep = "from" if r.get("access") == "read" else "into"
            parts.append(f"{r['title']}: the program {verb} {_b(n)} {where} {prep} {target}, "
                         f"which holds only {_b(cap)}{decl}.")
        else:
            what = _b(n) if n else "memory"
            where_rel = "before the start of" if r.get("relation") == "before" or "underflow" in r["kind"] \
                else "past the end of"
            parts.append(f"{r['title']}: the program {verb} {what} {where}, {where_rel} {target}{size}{decl}.")
        if r.get("allocated_at"):
            parts.append(f"The block was allocated at line {r['allocated_at']['line']}.")
        parts.append("Check the length before copying, or use a bounded function "
                     "(snprintf / safe_copy / safe_concat).")
    elif r["kind"] == "heap-use-after-free":
        parts.append(f"Use after free: memory was {r.get('access', 'accessed')} {where} after it was freed")
        if r.get("freed_at"):
            parts[-1] += f" at line {r['freed_at']['line']}"
        parts[-1] += "."
        parts.append("Set the pointer to NULL after free() and do not use it again.")
    elif r["kind"] == "double-free":
        parts.append(f"Double free {where}: this block was already freed"
                     + (f" at line {r['freed_at']['line']}." if r.get("freed_at") else "."))
        parts.append("Free each block exactly once, e.g. from a single clean-up point, and set it to NULL.")
    elif r["kind"] == "SEGV":
        parts.append(f"Segmentation fault {where}: the program used an invalid pointer "
                     "(for example NULL from a failed malloc, or an out-of-range index).")
    else:
        parts.append(f"{r['title']} {where}. {r['description']}")
    return " ".join(parts)
