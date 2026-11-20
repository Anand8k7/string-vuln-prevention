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
│   └── lib/          safe_string.h/.c + input handler
├── tests/            test runner that prints a PASS/FAIL table
├── analysis/         cppcheck + ASan + valgrind script; logs/ holds output
├── docs/report/      final project report (report.md)
├── screenshots/      terminal captures used in the report
├── Makefile
└── .github/workflows/ci.yml   build + test + cppcheck on every push
```

---

## 3. Requirements

- Linux (tested on Ubuntu 24.04 in GitHub Codespaces)
- `gcc` (tested with 13.3), `make`
- `cppcheck` (tested with 2.13)
- `valgrind` (tested with 3.22)

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
make test       # run the test suite (PASS/FAIL table)
make analyze    # cppcheck + ASan + valgrind, logs in analysis/logs/
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

## 6. Project status

- [x] Phase 1 – Skeleton, Makefile, README
- [x] Phase 2 – Safe string library and unit tests
- [x] Phase 3 – Q1: `strcpy`/`strcat` overflow (vulnerable + secure + tests)
- [x] Phase 4 – Q2: input validation and format strings (vulnerable + secure + tests)
- [x] Phase 5 – Analysis script and CI workflow
- [ ] Phase 6 – Final report (`docs/report/report.md`)
