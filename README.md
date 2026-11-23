# Implementing Prevention Methods for String Vulnerabilities

**Course:** CYE551 – Secure Coding Using C/C++
**Department:** CSE (Cyber Security), M. S. Ramaiah Institute of Technology (MSRIT)
**Semester:** B.E. 5th Semester – Mini Project
**Guide:** Prof. Shankaramma

| Name              | USN        |
|-------------------|------------|
| Yuval             | 1MS24CY021 |
| Anand             | 1MS24CY010 |
| Sathish Kumar S   | 1MS24CY055 |

---

## 1. Overview

C strings are plain `char` arrays terminated by `'\0'`. The standard library
functions that work on them (`strcpy`, `strcat`, `sprintf`, `gets`,
`scanf("%s")`, …) do **not** know the size of the destination buffer, which
makes string handling one of the most common sources of memory-safety bugs.

This project demonstrates common string vulnerabilities in deliberately
unsafe programs, then removes them with a small safe-string library and a
validated input pipeline. Each fix is checked with static analysis
(Cppcheck), dynamic analysis (AddressSanitizer, Valgrind) and a test suite.

### Workflow

```
User Input → Input Validation → Length & Boundary Checking
           → Safe String Handling → Output Verification → Result
```

### Modules

| # | Module                              | What it does |
|---|-------------------------------------|--------------|
| 1 | Input Handling                      | Bounded reads from `stdin` (`fgets`), `argv`, and files |
| 2 | Validation                          | Allowed-character whitelist, format, max length; invalid input is rejected |
| 3 | Safe String Operations              | `safe_copy`, `safe_concat`, `safe_format`: bounded, always `'\0'`-terminated, report truncation |
| 4 | Vulnerability Detection / Analysis  | Cppcheck + AddressSanitizer + Valgrind on vulnerable and secure builds |
| 5 | Testing & Evaluation                | Normal, boundary, invalid and oversized inputs, vulnerable vs. protected |

### Coding questions

| Q  | Vulnerability | Prevention |
|----|---------------|------------|
| Q1 | Buffer overflow through `strcpy` / `strcat` | Bounded copy/concat and length checks |
| Q2 | Improper input validation and unsafe formatting (`scanf("%s")`, `sprintf`, `printf(user_input)`) | `fgets`, whitelist validation, `snprintf`, fixed format strings |

---

## 2. Repository layout

```
.
├── src/
│   ├── vulnerable/   deliberately unsafe demo programs (local input only)
│   ├── secure/       fixed versions of the same programs
│   ├── lib/          safe_string.h/.c + input handler
│   └── examples/     20 small examples, each vulnerable.c + secure.c
├── tests/            test runner that prints a PASS/FAIL table
├── analysis/         cppcheck + ASan + valgrind script; logs/ holds output
├── docs/report/      final project report (report.md)
├── web/              local web app (Flask): scanner, runtime check, input tester, examples
├── screenshots/      terminal captures used in the report
├── demo.sh           step-by-step Q1/Q2 demo (vulnerable vs secure, ASan, cppcheck)
├── Makefile
└── .github/workflows/ci.yml   build + test + cppcheck on every push
```

---

## 3. Requirements

- Linux (tested on Ubuntu 24.04 in GitHub Codespaces)
- `gcc` (tested with 13.3), `make`
- `cppcheck` (tested with 2.13)
- `valgrind` (tested with 3.22)
- Python 3 and Flask, only for the web app (tested with Python 3.14, Flask 3.1)

Install on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cppcheck valgrind
```

---

## 4. Build and run

```bash
make            # build vulnerable + secure programs
make vulnerable # only the unsafe demos   -> bin/vulnerable/
make secure     # only the fixed versions -> bin/secure/
make asan       # both, with AddressSanitizer + UBSan -> bin/asan/
make examples   # the 20 small examples, 4 builds each -> bin/examples/
make test       # run the test suite (PASS/FAIL table)
make analyze    # cppcheck + ASan + valgrind, logs in analysis/logs/
make web        # build everything and start the web app on http://127.0.0.1:5000
make clean      # remove build output and logs
```

### Build flags

| Build      | Key flags | Purpose |
|------------|-----------|---------|
| vulnerable | `-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0` | Protections disabled on purpose so the bugs can be observed |
| secure     | `-Wall -Wextra -Werror -Wformat=2 -Wformat-security -Wconversion -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -pie -z relro -z now` | Warnings are errors, plus compiler/linker hardening |
| asan       | `-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer` | Runtime detection of overflows and undefined behaviour |

### Safe string library (`src/lib/`)

All functions take the **total** buffer size (`sizeof buf`), never write past
it, always leave a `'\0'`, and **report** truncation instead of hiding it.

| Function | Replaces | Returns |
|----------|----------|---------|
| `safe_copy(dst, size, src)` | `strcpy`, `strncpy` | `SS_OK`, `SS_TRUNCATED`, `SS_ERR_NULL`, `SS_ERR_SIZE` |
| `safe_concat(dst, size, src)` | `strcat`, `strncat` | as above + `SS_ERR_UNTERMINATED` |
| `safe_format(dst, size, fmt, ...)` | `sprintf` | as above + `SS_ERR_FORMAT` |
| `safe_strlen(s, max)` | `strlen` on untrusted data | length, never reads more than `max` bytes |
| `validate_input(s, min, max, charset, extra, &pos)` | ad-hoc checks | `VAL_OK`, `VAL_ERR_TOO_LONG`, `VAL_ERR_EMPTY`, `VAL_ERR_BAD_CHAR`, … |
| `validate_integer(s, min, max, &out)` | `atoi`, `scanf("%d")` | `VAL_OK`, `VAL_ERR_NOT_NUMBER`, `VAL_ERR_RANGE`, … |
| `input_read_line(fp, buf, size, &len)` | `gets`, `scanf("%s")` | `IN_OK`, `IN_TOO_LONG` (rest of line drained), `IN_EOF`, `IN_ERR_NUL_BYTE`, … |
| `input_from_arg(argc, argv, i, buf, size)` | `strcpy(buf, argv[i])` | `IN_OK`, `IN_TOO_LONG`, `IN_ERR_MISSING`, … |
| `input_read_file(path, buf, size, &len)` | unchecked `fread`/`fgets` loops | `IN_OK`, `IN_TOO_LONG`, `IN_ERR_IO`, … |

Unit tests (`tests/test_safe_string.c`, `tests/test_input_handler.c`) cover
normal, boundary, invalid and oversized inputs. Each test also checks
**guard bytes** placed after the buffer, and the test binaries run under
AddressSanitizer + UBSan.

### Q1 – Buffer overflow via `strcpy` / `strcat`

```bash
make all asan
./bin/vulnerable/q1_overflow alice cse                 # normal
./bin/vulnerable/q1_overflow AAAAAAAAAAAAAAAAAAAA cse  # role overwritten -> "AAAA"
./bin/asan/vulnerable_q1_overflow abcdefghijklmno abcdefghijklmno  # ASan: stack-buffer-overflow
./bin/secure/q1_overflow AAAAAAAAAAAAAAAAAAAA cse      # REJECTED: username is too long
bash tests/scenarios/q1_overflow.sh                    # 17 cases, vulnerable vs secure
```

| Source | Description |
|--------|-------------|
| `src/vulnerable/q1_overflow.c` | `strcpy`/`strcat` into `username[16]`, `greeting[32]`, `path[32]` with no checks |
| `src/secure/q1_overflow.c` | Workflow: bounded input → whitelist validation → `safe_copy`/`safe_concat`/`safe_format` (reject on `SS_TRUNCATED`) → output verification |
| `tests/scenarios/q1_overflow.sh` | Runs every case on 4 builds (vulnerable, vulnerable+ASan, secure, secure+ASan) |

### Q2 – Input validation and unsafe formatting

`q2_format` is a small feedback form that reads **Name**, **Age** and
**Message** from standard input, one per line.

```bash
make all asan
printf 'alice\n21\nhello\n'            | ./bin/vulnerable/q2_format   # normal
printf 'alice\n21\n%%p.%%p.%%p.%%p\n'      | ./bin/vulnerable/q2_format   # printf(msg): stack values printed
printf 'alice\n21\n50%% off!\n'          | ./bin/vulnerable/q2_format   # even innocent text is misformatted
printf 'alice\nabc\nhello\n'           | ./bin/vulnerable/q2_format   # unchecked scanf("%d"): fields shift
printf 'alice\n21\n%%p.%%p.%%p.%%p\n'      | ./bin/secure/q2_format       # printed literally
printf 'alice\nabc\nhello\n'           | ./bin/secure/q2_format       # REJECTED: age is not a whole number
bash tests/scenarios/q2_format.sh                                     # 26 cases, vulnerable vs secure
```

| Source | Description |
|--------|-------------|
| `src/vulnerable/q2_format.c` | `scanf("%s")`, unchecked `scanf("%d")`, `sprintf` into `record[64]`, `printf(msg)` |
| `src/secure/q2_format.c` | `fgets`-based `input_read_line`, whitelist validation, `validate_integer` (1–120), `safe_format` (reject on `SS_TRUNCATED`), fixed format strings only |
| `tests/scenarios/q2_format.sh` | Runs every case on 4 builds; for accepted input it also checks that the message is echoed **literally** and the simulated secret never appears |

### 20 additional examples (`src/examples/`)

Each directory `src/examples/eNN_name/` holds a `vulnerable.c` (bug marked
`BUG:`) and a `secure.c` (fix marked `FIX:`). `make examples` builds four
versions of each into `bin/examples/eNN_name/`; `tests/scenarios/examples.sh`
runs 90 test cases on them (part of `make test`).

| # | Example | Vulnerability | Fix |
|---|---------|---------------|-----|
| 1 | `e01_strcpy_overflow` | `strcpy` overflow | `safe_copy` |
| 2 | `e02_strcat_overflow` | `strcat` overflow | `safe_concat` |
| 3 | `e03_format_string` | `printf(user_input)` | `printf("%s", …)` |
| 4 | `e04_scanf_no_width` | `scanf("%s")` without width | `scanf("%7s")` + check |
| 5 | `e05_gets` | `gets()` | `input_read_line` (`fgets`) |
| 6 | `e06_off_by_one_loop` | off-by-one in a loop | `>=` check, `i < len`, explicit `'\0'` |
| 7 | `e07_strncpy_no_terminator` | missing `'\0'` after `strncpy` | `safe_copy` |
| 8 | `e08_sprintf_overflow` | `sprintf` | `snprintf` + return check |
| 9 | `e09_length_integer_overflow` | integer overflow in a length calculation | `size_t` + wrap and limit checks |
| 10 | `e10_out_of_bounds_index` | out-of-bounds index | `validate_integer` range |
| 11 | `e11_unterminated_strlen` | `strlen` on unterminated data | `safe_strlen` + `%.*s` |
| 12 | `e12_memcpy_wrong_size` | `memcpy` with the wrong size | size from data, checked against destination |
| 13 | `e13_command_injection` | command injection via `system()` | no shell + whitelist |
| 14 | `e14_path_traversal` | path traversal | whitelist + `realpath` containment |
| 15 | `e15_use_after_free` | use-after-free | use, free once, `NULL` |
| 16 | `e16_double_free` | double free | single clean-up point |
| 17 | `e17_unchecked_malloc` | unchecked `malloc` | range check + `NULL` check |
| 18 | `e18_heap_overflow_malloc` | heap overflow (`malloc(strlen)`) | `len + 1` + `safe_copy` |
| 19 | `e19_signed_unsigned_length` | signed/unsigned length mismatch | both bounds checked, `size_t` |
| 20 | `e20_strtok_reentrancy` | `strtok` vs `strtok_r` | `strtok_r` + validation |

Results and the full comparison table are in Section 9 of the report.

### Analysis (`make analyze`)

`analysis/run_analysis.sh` runs five checks on **both** versions and writes
every log to `analysis/logs/` (summary in `analysis/logs/summary.txt`):

| Step | Tool | What it finds |
|------|------|---------------|
| 1 | gcc `-Wall -Wextra -Wformat=2 -Wformat-overflow=2 ...` | non-literal format strings, provable `sprintf` overflows, ignored `scanf` results |
| 2 | Cppcheck `--enable=all` | `scanf("%s")` without width, style issues |
| 3 | `analysis/banned_functions.py` | every `strcpy`/`strcat`/`sprintf`/`gets`/`scanf("%s")`/`printf(var)` call |
| 4 | AddressSanitizer + UBSan | stack buffer overflows at run time |
| 5 | Valgrind memcheck | invalid reads, uninitialised values, wild jumps, leaks |

The script exits non-zero only if something is found in the **secure** code.

### Web app (`web/`)

A local web page where you can paste input or C code and check it for string
vulnerabilities. Backend: Python Flask (`web/app.py`). Frontend: one HTML page
with plain CSS and JavaScript (`web/static/`), no frameworks.

```bash
pip install -r web/requirements.txt   # Flask
make web                              # = make all asan + python3 web/app.py
# or, if the programs are already built:
python3 web/app.py
```

Then open **http://127.0.0.1:5000/**.

| Tab | What it does |
|-----|--------------|
| 1 · Code Scanner | Paste C/C++ code. Our rule-based scanner (`web/scanner.py`) and cppcheck look for `strcpy`, `strcat`, `gets`, `sprintf`, `vsprintf`, `scanf("%s")` without a width, `printf`/`fprintf` with a non-literal format, `strncpy` without `'\0'`, `memcpy` sized by `strlen` or by the source, `system()`, `<=` off-by-one loops, `malloc(strlen(x))` without `+ 1`, unchecked `malloc`/`scanf` results, use after free and double free. Each finding shows its line (highlighted in the code), CWE ID, severity, a short explanation and the safe replacement, plus a summary score from 0 to 100. |
| 2 · Runtime Check | Paste a C program plus stdin and arguments. It is compiled with `gcc -fsanitize=address,undefined -g` and run. The ASan / UBSan / LeakSanitizer report is explained in plain English (type of bug, line, variable, bytes), and the raw output is in a collapsible box. |
| 3 · Input Tester | Type name, role, age and message. The same input goes to `q1_overflow` (arguments) and `q2_format` (stdin): vulnerable, vulnerable + ASan, secure and secure + ASan, side by side, with badges **EXPLOITED / CRASHED / ASan ERROR** vs **REJECTED / SAFE**. |
| 4 · Examples | Pick one of the 20 examples to see `vulnerable.c` and `secure.c` side by side (`BUG:` / `FIX:` lines highlighted). Each test case from `tests/scenarios/examples.sh` has its own Run button that runs it on all 4 builds and shows PASS/FAIL. |

Tabs 1–3 have a **Load sample** button, so each demo takes one click.

**Safety.** The app runs code you paste, so it is for local educational use only:

* the server binds to `127.0.0.1` only and shows a "For local educational use only" banner;
* every compile and run happens in a new temporary directory that is deleted afterwards;
* limits: 5 s wall clock and 5 s CPU per run, 256 MB memory (ASan builds use ASan's
  own 256 MB RSS limit), 1 MB file size, 64 open files, a process limit, max 20 KB
  of code, max 4 KB of input, output cut to 64 KB;
* no `shell=True`: every command is an argument list;
* programs run inside `unshare --user --net`, so they have no network and run as
  `nobody`. If that is not available, the app prints a note at start-up and runs
  without network isolation. If the server is started as root, programs are
  switched to `nobody` before they start;
* the Examples tab only runs the fixed test cases, never free-form input.

It does not hide your files from the code it runs: a pasted program can still
read the files your user can read. Only run code you understand.

Check every tab from the command line while the app is running:

```bash
bash web/smoke_test.sh        # 23 curl checks, prints PASS/FAIL
```

**Screenshots** (placeholders; capture them with the app running):

| File | What to capture |
|------|-----------------|
| `screenshots/28_web_scanner.png` | Code Scanner after *Load sample → Scan code*: score, highlighted lines, findings |
| `screenshots/29_web_runtime.png` | Runtime Check with the *Stack overflow (strcpy)* sample: verdict and plain-English explanation |
| `screenshots/30_web_input_tester.png` | Input Tester with *Long name (overflow)*: Q1 and Q2 badges side by side |
| `screenshots/31_web_examples.png` | Examples tab, `e13_command_injection`, case E13-2 |

### Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request (Ubuntu 24.04):
build → `make test` → Cppcheck on secure code (must be clean) → banned-API
scan on secure code (must be clean) → `make analyze`. The logs are uploaded
as the `analysis-logs` artifact.

---

## 5. Safety note

The programs in `src/vulnerable/` are intentionally insecure **teaching
examples**. They only read local input (keyboard, command-line arguments,
local files), contain no exploit payloads, and are built without
protections only so that the bugs can be observed. The Q2 format-string
tests only *read* memory (`%p`, `%lx`, `%s`) to show a simulated secret
being leaked; no `%n` (memory write) input is used. Do not reuse that code.

---

## 6. Report and screenshots

* **Report:** [`docs/report/report.md`](docs/report/report.md) — aim, concept,
  setup, procedure, full code, real outputs, security analysis (CWE / CERT C),
  test cases, observations and learning outcomes for Q1 and Q2.
* **Screenshots:** [`screenshots/SCREENSHOT_LIST.md`](screenshots/SCREENSHOT_LIST.md)
  lists every figure with its exact command and report section.
* The output blocks in the report are real program output. To regenerate them:

  ```bash
  bash docs/report/collect_outputs.sh     # runs every command, saves docs/report/outputs/
  python3 docs/report/render_report.py    # copies the outputs into report.md
  ```

## 7. Project status

- [x] Phase 1 – Skeleton, Makefile, README
- [x] Phase 2 – Safe string library and unit tests
- [x] Phase 3 – Q1: `strcpy`/`strcat` overflow (vulnerable + secure + tests)
- [x] Phase 4 – Q2: input validation and format strings (vulnerable + secure + tests)
- [x] Phase 5 – Analysis script and CI workflow
- [x] Phase 6 – Final report (`docs/report/report.md`)
- [x] Local web app (`web/`, `make web`)
