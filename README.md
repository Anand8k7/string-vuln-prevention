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

---

## 5. Safety note

The programs in `src/vulnerable/` are intentionally insecure **teaching
examples**. They only read local input (keyboard, command-line arguments,
local files), contain no exploit payloads, and are built without
protections only so that the bugs can be observed. Do not reuse that code.

---

## 6. Project status

- [x] Phase 1 – Skeleton, Makefile, README
- [x] Phase 2 – Safe string library and unit tests
- [ ] Phase 3 – Q1: `strcpy`/`strcat` overflow (vulnerable + secure + tests)
- [ ] Phase 4 – Q2: input validation and format strings (vulnerable + secure + tests)
- [ ] Phase 5 – Analysis script and CI workflow
- [ ] Phase 6 – Final report (`docs/report/report.md`)
