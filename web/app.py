"""
app.py - local web app for the CYE551 string-vulnerability project.

    python3 web/app.py          ->  http://127.0.0.1:5000

Tabs: Code Scanner, Runtime Check, Input Tester, Examples.
For local educational use only. The server binds to 127.0.0.1, and every
compile/run goes through sandbox.py (temp dir, time/CPU/memory/file
limits, no network, no shell).
"""
import os
import re
import shlex
import shutil
import sys

from flask import Flask, jsonify, request, send_from_directory

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asan_explain  # noqa: E402
import examples  # noqa: E402
import sandbox  # noqa: E402
import samples  # noqa: E402
import scanner  # noqa: E402

ROOT = examples.ROOT
BIN = os.path.join(ROOT, "bin")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

MAX_CODE = 20 * 1024
MAX_INPUT = 4 * 1024
HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", "5000"))

app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


class BadRequest(Exception):
    pass


@app.errorhandler(BadRequest)
def _bad(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(413)
def _too_big(_e):
    return jsonify({"error": "Request too large (max 64 KB)."}), 413


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BadRequest("Expected a JSON object.")
    return data


def text_field(data, key, limit, required=False):
    v = data.get(key, "")
    if not isinstance(v, str):
        raise BadRequest(f"'{key}' must be a string.")
    if required and not v.strip():
        raise BadRequest(f"'{key}' is empty.")
    if len(v.encode("utf-8")) > limit:
        raise BadRequest(f"'{key}' is too long (max {limit // 1024} KB).")
    if "\x00" in v:
        raise BadRequest(f"'{key}' must not contain NUL bytes.")
    return v


def lang_of(data):
    lang = data.get("lang", "c")
    if lang not in ("c", "cpp"):
        raise BadRequest("'lang' must be 'c' or 'cpp'.")
    return lang


# -----------------------------------------------------------------------------
# Pages / metadata
# -----------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/api/info")
def info():
    tools = {t: shutil.which(t) is not None for t in ("gcc", "g++", "cppcheck")}
    missing = [p for p in ("vulnerable/q1_overflow", "secure/q1_overflow",
                           "asan/vulnerable_q1_overflow", "asan/secure_q1_overflow",
                           "vulnerable/q2_format", "secure/q2_format",
                           "asan/vulnerable_q2_format", "asan/secure_q2_format")
               if not os.access(os.path.join(BIN, p), os.X_OK)]
    return jsonify({"tools": tools, "limits": sandbox.describe_limits(),
                    "missing_binaries": missing,
                    "examples_built": os.path.isdir(os.path.join(BIN, "examples"))})


@app.get("/api/samples")
def get_samples():
    return jsonify({"scan": samples.SCAN_SAMPLES, "runtime": samples.RUNTIME_SAMPLES,
                    "input": samples.INPUT_SAMPLES})


# -----------------------------------------------------------------------------
# Tab 1: Code Scanner
# -----------------------------------------------------------------------------
CPPCHECK_SEVERITY = {"error": "high", "warning": "medium", "style": "low",
                     "performance": "low", "portability": "low"}
CPPCHECK_IGNORE = {"missingIncludeSystem", "missingInclude", "checkersReport",
                   "unusedFunction", "normalCheckLevelMaxBranches", "toomanyconfigs"}


def run_cppcheck(code, lang):
    if not shutil.which("cppcheck"):
        return {"available": False, "findings": []}
    fname = "main.cpp" if lang == "cpp" else "main.c"
    with sandbox.temp_workdir() as wd:
        with open(os.path.join(wd, fname), "w", encoding="utf-8") as f:
            f.write(code)
        r = sandbox.run(["cppcheck", "--enable=warning,style,performance,portability",
                         "--std=c++17" if lang == "cpp" else "--std=c11",
                         "--inline-suppr", "-q",
                         "--template={line}\x1f{severity}\x1f{id}\x1f{cwe}\x1f{message}",
                         fname], wd, timeout=15, cpu=15, limit_memory=False)
    found = []
    for line in r["output"].splitlines():
        p = line.split("\x1f")
        if len(p) != 5 or p[2] in CPPCHECK_IGNORE or not p[0].isdigit():
            continue
        sev = CPPCHECK_SEVERITY.get(p[1])
        if sev is None:
            continue
        found.append({"line": int(p[0]), "severity": sev, "id": p[2],
                      "cwe": f"CWE-{p[3]}" if p[3] not in ("", "0") else "",
                      "message": p[4], "cppcheck_severity": p[1]})
    return {"available": True, "findings": found, "timed_out": r["timed_out"]}


@app.post("/api/scan")
def api_scan():
    data = body()
    code = text_field(data, "code", MAX_CODE, required=True)
    lang = lang_of(data)
    rules = scanner.scan(code)
    cpp = run_cppcheck(code, lang)

    # A cppcheck finding on a line the rules already flagged is attached to
    # that finding as confirmation instead of being counted twice.
    combined = list(rules)
    by_line = {}
    for f in rules:
        by_line.setdefault(f["line"], []).append(f)
    for c in cpp["findings"]:
        if c["line"] in by_line:
            by_line[c["line"]][0].setdefault("cppcheck", []).append(c)
            continue
        combined.append({
            "rule": "cppcheck:" + c["id"], "line": c["line"], "cwe": c["cwe"],
            "severity": c["severity"], "title": f"cppcheck: {c['id']}",
            "explain": c["message"],
            "fix": "See the cppcheck message; fix the code it points at.",
            "detail": f"cppcheck severity: {c['cppcheck_severity']}",
            "code": code.split("\n")[c["line"] - 1].strip() if c["line"] - 1 < len(code.split("\n")) else "",
            "source": "cppcheck",
        })
    combined.sort(key=lambda f: (f["line"], -scanner.SEVERITY_WEIGHT[f["severity"]]))
    return jsonify({"findings": combined, "summary": scanner.score(combined),
                    "rule_count": len(rules), "cppcheck": {
                        "available": cpp["available"], "count": len(cpp["findings"])}})


# -----------------------------------------------------------------------------
# Tab 2: Runtime Check
# -----------------------------------------------------------------------------
DIAG_RE = re.compile(r"^main\.(?:c|cpp):(\d+):(\d+): (warning|error|note): (.*)$", re.M)


@app.post("/api/runtime")
def api_runtime():
    data = body()
    code = text_field(data, "code", MAX_CODE, required=True)
    stdin = text_field(data, "stdin", MAX_INPUT)
    args_s = text_field(data, "args", MAX_INPUT)
    if len((stdin + args_s).encode("utf-8")) > MAX_INPUT:
        raise BadRequest("stdin + arguments must be at most 4 KB together.")
    lang = lang_of(data)
    try:
        args = shlex.split(args_s)
    except ValueError as e:
        raise BadRequest(f"Could not parse arguments: {e}")
    compiler = "g++" if lang == "cpp" else "gcc"
    if not shutil.which(compiler):
        raise BadRequest(f"{compiler} is not installed.")
    src = "main.cpp" if lang == "cpp" else "main.c"
    std = "-std=gnu++17" if lang == "cpp" else "-std=gnu17"

    with sandbox.temp_workdir() as wd:
        with open(os.path.join(wd, src), "w", encoding="utf-8") as f:
            f.write(code)
        cc = sandbox.run([compiler, std, "-g", "-O0", "-fno-omit-frame-pointer",
                          "-fsanitize=address,undefined", "-Wall", "-Wextra",
                          "-Wformat=2", "-fdiagnostics-color=never", src, "-o", "prog"],
                         wd, timeout=20, cpu=20, limit_memory=False)
        diags = [{"line": int(m.group(1)), "col": int(m.group(2)), "kind": m.group(3),
                  "message": m.group(4)} for m in DIAG_RE.finditer(cc["output"])]
        compiled = cc["rc"] == 0 and os.path.exists(os.path.join(wd, "prog"))
        result = {"compile": {"ok": compiled, "output": cc["output"], "diagnostics": diags,
                              "timed_out": cc["timed_out"]}}
        if not compiled:
            result["verdict"] = {"level": "neutral", "label": "COMPILE ERROR",
                                 "text": "The code did not compile; see the compiler output."}
            return jsonify(result)
        run = sandbox.run(["./prog"] + args, wd, stdin=stdin.encode("utf-8"), asan=True)

    findings = asan_explain.explain(run["output"], (src,))
    result["run"] = run
    result["findings"] = findings
    if findings:
        kinds = ", ".join(sorted({f["title"] for f in findings}))
        result["verdict"] = {"level": "bad", "label": "ASan ERROR",
                             "text": f"Sanitizer found: {kinds}."}
    elif run["limit"] == "time":
        result["verdict"] = {"level": "bad", "label": "TIMEOUT",
                             "text": f"Stopped by the {sandbox.TIMEOUT_S} s time/CPU limit."}
    elif run["limit"] == "output":
        result["verdict"] = {"level": "bad", "label": "OUTPUT LIMIT",
                             "text": "Stopped: the program wrote more than 1 MB of output."}
    elif run["signal"]:
        result["verdict"] = {"level": "bad", "label": "CRASHED",
                             "text": f"Program was killed by {run['signal']}."}
    else:
        result["verdict"] = {"level": "good", "label": "CLEAN",
                             "text": f"No sanitizer errors for this input (exit code {run['rc']})."}
    return jsonify(result)


# -----------------------------------------------------------------------------
# Tab 3: Input Tester (Q1 + Q2, vulnerable vs secure, plain + ASan)
# -----------------------------------------------------------------------------
Q2_SECRET = "5ec12e7ab1e"   # value of secret_token in q2_format.c, as %lx prints it


def badge(level, label, text=""):
    return {"level": level, "label": label, "text": text}


def common_badge(run, findings):
    if findings:
        f = findings[0]
        return badge("bad", "ASan ERROR", f["plain"])
    if run["limit"] == "time":
        return badge("bad", "TIMEOUT", "Stopped by the time limit.")
    if run["limit"] == "output":
        return badge("bad", "OUTPUT LIMIT", "Stopped: more than 1 MB of output.")
    if run["signal"]:
        return badge("bad", "CRASHED", f"Killed by {run['signal']}.")
    return None


def q1_defect(out, user):
    role = re.search(r"^Role     : (.*)$", out, re.M)
    uname = re.search(r"^Username : (.*)$", out, re.M)
    first = out.split("\n", 1)[0]
    if role:
        if role.group(1) == "":
            return 'role wiped to ""'
        if role.group(1) != "guest":
            return f'role overwritten with "{role.group(1)}"'
    if uname and first != f"Welcome, {uname.group(1)}!":
        return "greeting corrupted"
    return None


def q2_defect(out, name, age, msg):
    if Q2_SECRET in out.lower():
        return "secret_token leaked through the format string"
    echo = re.search(r"^Your message: (.*)$", out, re.M)
    if "%" in msg and (not echo or echo.group(1) != msg):
        return "format string interpreted (printf(msg))"
    rec = re.search(r"^Saved record: (.*)$", out, re.M)
    rec_s = rec.group(1) if rec else ""
    if len(rec_s) > 63:
        return f"record[64] overflowed ({len(rec_s) + 1} bytes written)"
    got = re.search(r" age=(-?\d*) msg=", rec_s)
    if re.fullmatch(r"-?\d+", age) and got and got.group(1) != age:
        return f"age silently stored as {got.group(1)}"
    if rec and rec_s != f"name={name} age={age} msg={msg}":
        return "fields mixed up (scanf read the wrong data)"
    return None


def classify_vulnerable(run, findings, defect, invalid_reason):
    b = common_badge(run, findings)
    if b:
        return b
    if defect:
        return badge("bad", "EXPLOITED", defect)
    if run["rc"] == 1 and "Usage" in run["output"]:
        return badge("neutral", "USAGE", "Program printed its usage message.")
    if invalid_reason:
        return badge("warn", "BAD INPUT ACCEPTED", invalid_reason)
    return badge("neutral", "NO EFFECT", "No visible problem for this input.")


def classify_secure(run, findings):
    b = common_badge(run, findings)
    if b:
        return b
    if run["rc"] == 2:
        m = re.search(r"REJECTED: (.*)", run["output"])
        return badge("good", "REJECTED", m.group(1) if m else "Input rejected.")
    if run["rc"] == 0:
        return badge("good", "SAFE", "Input accepted and handled safely.")
    if run["rc"] == 1:
        return badge("neutral", "USAGE", "Program printed its usage message.")
    return badge("warn", f"EXIT {run['rc']}", "Unexpected exit code.")


def q2_invalid(name, age, msg):
    """Why this input should be rejected (mirrors the secure rules), or None."""
    if not re.fullmatch(r"\d+", age or "") or not 1 <= int(age) <= 120:
        return f'age "{age}" is not a whole number from 1 to 120'
    if not 1 <= len(name) <= 15:
        return "name must be 1-15 characters"
    if len(msg) > 40:
        return "message is longer than 40 characters"
    return None


def run_program(path, args=(), stdin=b"", cwd=None, asan=False):
    if not os.access(path, os.X_OK):
        raise BadRequest(f"{os.path.relpath(path, ROOT)} is missing - run 'make all asan' first.")
    with sandbox.temp_workdir() as wd:
        r = sandbox.run([path] + list(args), wd, stdin=stdin, cwd=cwd or wd, asan=asan)
    src = (os.path.basename(path).replace("vulnerable_", "").replace("secure_", "") + ".c",
           "vulnerable.c", "secure.c")
    return r, asan_explain.explain(r["output"], src) if asan else []


@app.post("/api/input-test")
def api_input_test():
    data = body()
    name = text_field(data, "name", MAX_INPUT)
    role = text_field(data, "role", MAX_INPUT)
    age = text_field(data, "age", MAX_INPUT)
    msg = text_field(data, "message", MAX_INPUT)
    if len((name + role + age + msg).encode("utf-8")) > MAX_INPUT:
        raise BadRequest("All fields together must be at most 4 KB.")
    if any(c in s for s in (name, role, age, msg) for c in "\r\n"):
        raise BadRequest("Fields must be single lines.")

    out = {"q1": {"args": [name, role], "runs": []},
           "q2": {"stdin": f"{name}\n{age}\n{msg}\n", "runs": []}}
    q1_invalid = None
    if not 1 <= len(name) <= 15:
        q1_invalid = "username must be 1-15 characters"
    for label, path, asan, secure in (
            ("Vulnerable", "vulnerable/q1_overflow", False, False),
            ("Vulnerable + ASan", "asan/vulnerable_q1_overflow", True, False),
            ("Secure", "secure/q1_overflow", False, True),
            ("Secure + ASan", "asan/secure_q1_overflow", True, True)):
        r, fs = run_program(os.path.join(BIN, path), [name, role], asan=asan)
        b = classify_secure(r, fs) if secure else \
            classify_vulnerable(r, fs, q1_defect(r["output"], name), q1_invalid)
        out["q1"]["runs"].append({"label": label, "binary": f"bin/{path}", "secure": secure,
                                  "badge": b, "run": r, "findings": fs})

    stdin = out["q2"]["stdin"].encode("utf-8")
    inv = q2_invalid(name, age, msg)
    for label, path, asan, secure in (
            ("Vulnerable", "vulnerable/q2_format", False, False),
            ("Vulnerable + ASan", "asan/vulnerable_q2_format", True, False),
            ("Secure", "secure/q2_format", False, True),
            ("Secure + ASan", "asan/secure_q2_format", True, True)):
        r, fs = run_program(os.path.join(BIN, path), stdin=stdin, asan=asan)
        b = classify_secure(r, fs) if secure else \
            classify_vulnerable(r, fs, q2_defect(r["output"], name, age, msg), inv)
        out["q2"]["runs"].append({"label": label, "binary": f"bin/{path}", "secure": secure,
                                  "badge": b, "run": r, "findings": fs})
    return jsonify(out)


# -----------------------------------------------------------------------------
# Tab 4: Examples
# -----------------------------------------------------------------------------
_EXAMPLES = None


def all_examples():
    global _EXAMPLES
    if _EXAMPLES is None:
        _EXAMPLES = {e["name"]: e for e in examples.list_examples()}
    return _EXAMPLES


@app.get("/api/examples")
def api_examples():
    return jsonify([{k: e[k] for k in ("name", "number", "vulnerability", "fix", "cwe")}
                    for e in all_examples().values()])


@app.get("/api/examples/<name>")
def api_example(name):
    e = all_examples().get(name)
    src = examples.read_sources(name) if e else None
    if not src:
        return jsonify({"error": "Unknown example."}), 404
    return jsonify({**e, **src})


def example_defect(case, out):
    re_s = case["def_re"]
    if re_s:
        neg = re_s.startswith("!")
        pat = re.compile(re_s[1:] if neg else re_s, re.M)
        hit = bool(pat.search(out))
        if hit != neg:
            return case["def_label"]
    return None


@app.post("/api/examples/<name>/run")
def api_example_run(name):
    e = all_examples().get(name)
    if not e:
        return jsonify({"error": "Unknown example."}), 404
    cid = body().get("case")
    case = next((c for c in e["cases"] if c["id"] == cid), None)
    if case is None:
        raise BadRequest("Unknown test case.")
    d = os.path.join(BIN, "examples", name)
    stdin = case["stdin"].encode("utf-8")
    runs = []
    for label, b, asan, secure in (("Vulnerable", "vulnerable", False, False),
                                   ("Vulnerable + ASan", "vulnerable_asan", True, False),
                                   ("Secure", "secure", False, True),
                                   ("Secure + ASan", "secure_asan", True, True)):
        # run from the repository root: e14 reads tests/fixtures/... relative paths
        r, fs = run_program(os.path.join(d, b), case["args"], stdin=stdin, cwd=ROOT, asan=asan)
        if secure:
            bd = classify_secure(r, fs)
        else:
            defect = example_defect(case, r["output"])
            invalid = None
            if case["expect"] == "REJECT" and not re.search(
                    r"rejected|error|usage|no input|no such file", r["output"], re.I):
                invalid = "bad input accepted"
            bd = classify_vulnerable(r, fs, defect, invalid)
        runs.append({"label": label, "binary": f"bin/examples/{name}/{b}", "secure": secure,
                     "badge": bd, "run": r, "findings": fs})
    # Same PASS rule as the test suite: secure result matches the expectation,
    # the secure output matches SEC_RE for accepted input, ASan build is clean.
    s, sa = runs[2], runs[3]
    got = "ACCEPT" if s["run"]["rc"] == 0 else ("REJECT" if s["run"]["rc"] == 2 else "OTHER")
    ok = got == case["expect"] and not sa["findings"] and s["run"]["rc"] == sa["run"]["rc"]
    if ok and got == "ACCEPT" and case["sec_re"]:
        ok = re.search(case["sec_re"], s["run"]["output"], re.M) is not None
    return jsonify({"case": case, "runs": runs, "secure_result": got, "pass": ok})


if __name__ == "__main__":
    print(" * CYE551 String Vulnerability Lab - for local educational use only")
    print(f" * Open http://{HOST}:{PORT}/")
    if not sandbox.UNSHARE:
        print(" * Note: 'unshare --user --net' is not available; programs run "
              "without network isolation (limits still apply).")
    app.run(host=HOST, port=PORT, debug=False)
