# Screenshot list

Every screenshot used in [`docs/report/report.md`](../docs/report/report.md),
with the exact command to run and the report section it belongs to.
Save each image in this folder under the given filename; the report already
links to these paths, so the images appear automatically once they exist.

## Before you start

```bash
cd string-vuln-prevention
make clean && make all asan && make test >/dev/null   # build everything once
```

* Use a wide terminal (≥ 180 columns) or zoom out for the test tables.
* Clear the screen (`clear`) before each capture so only the relevant output is visible.
* Keep the command line visible in each screenshot.

## Phase 1 — Setup

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 1 | `01_toolchain_versions.png` | `gcc --version \| head -1; cppcheck --version; valgrind --version` | 4.3 Requirements / setup (Figure 1) |
| 2 | `02_repo_structure.png` | `tree -a -I '.git\|bin'` (install with `sudo apt-get install -y tree`) | 2.3 Repository structure (Figure 2) |
| 3 | `03_make_help.png` | `make help` | 2.4 Build configurations (Figure 3) |

## Phase 2 — Safe string library

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 4 | `04_unit_tests_safe_string.png` | `./bin/tests/test_safe_string` | 3.3 Unit tests (Figure 4) |
| 5 | `05_unit_tests_input_handler.png` | `./bin/tests/test_input_handler` | 3.3 Unit tests (Figure 5) |
| 6 | `06_valgrind_unit_tests.png` | `gcc -std=c11 -g -Isrc/lib tests/test_safe_string.c src/lib/*.c -o bin/vg_test && valgrind --leak-check=full ./bin/vg_test \| tail -5` | 3.3 Unit tests (Figure 6) |

## Phase 3 — Q1: `strcpy` / `strcat` overflow

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 7 | `07_q1_vuln_normal_vs_overflow.png` | `./bin/vulnerable/q1_overflow alice cse; ./bin/vulnerable/q1_overflow AAAAAAAAAAAAAAAA cse; ./bin/vulnerable/q1_overflow AAAAAAAAAAAAAAAAAAAA cse` | 4.6 Q1 expected output (Figure 7) |
| 8 | `08_q1_vuln_segfault.png` | `./bin/vulnerable/q1_overflow $(printf 'A%.0s' {1..100}) cse; echo "exit=$?"` | 4.6 Q1 expected output (Figure 8) |
| 9 | `09_q1_asan_stack_overflow.png` | `./bin/asan/vulnerable_q1_overflow abcdefghijklmno abcdefghijklmno` (capture the top part up to `SUMMARY:`) | 4.9 Q1 observations (Figure 9) |
| 10 | `10_q1_asan_misses_intra_struct.png` | `./bin/asan/vulnerable_q1_overflow AAAAAAAAAAAAAAAAAAAA cse` | 4.9 Q1 observations (Figure 10) |
| 11 | `11_q1_secure_rejects.png` | `./bin/secure/q1_overflow alice cse; ./bin/secure/q1_overflow AAAAAAAAAAAAAAAAAAAA cse; ./bin/secure/q1_overflow 'bob;ls' cse; ./bin/secure/q1_overflow abcdefghijklmno abcdefghijklmno` | 4.6 Q1 expected output (Figure 11) |
| 12 | `12_q1_test_table.png` | `bash tests/scenarios/q1_overflow.sh` (≈170 columns wide) | 4.8 Q1 test cases (Figure 12) |
| 21 | `21_q1_valgrind_ret_overwrite.png` | `valgrind -q ./bin/vulnerable/q1_overflow $(printf 'A%.0s' {1..100}) cse 2>&1 \| head -18` | 4.9 Q1 observations (Figure 21) |

## Phase 4 — Q2: input validation and format strings

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 13 | `13_q2_gcc_warnings.png` | `make clean && make vulnerable` | 5.9 Q2 observations (Figure 13) |
| 14 | `14_q2_vuln_format_leak.png` | `printf 'alice\n21\n%%p.%%p.%%p.%%p\n' \| ./bin/vulnerable/q2_format; printf 'alice\n21\n%%27$lx\n' \| ./bin/vulnerable/q2_format` | 5.6 Q2 expected output (Figure 14) |
| 15 | `15_q2_vuln_validation.png` | `printf 'alice\nabc\nhello\n' \| ./bin/vulnerable/q2_format; printf 'John Smith\n21\nhello\n' \| ./bin/vulnerable/q2_format; printf 'alice\n-5\nhello\n' \| ./bin/vulnerable/q2_format` | 5.6 Q2 expected output (Figure 15) |
| 16 | `16_q2_vuln_crash.png` | `printf 'alice\n21\n%%s%%s%%s%%s%%s%%s%%s%%s\n' \| ./bin/vulnerable/q2_format; echo "exit=$?"` | 5.6 Q2 expected output (Figure 16) |
| 17 | `17_q2_secure.png` | the commands of #14, #15 and #16 with `./bin/secure/q2_format` instead of `./bin/vulnerable/q2_format` | 5.6 Q2 expected output (Figure 17) |
| 18 | `18_q2_asan_record_overflow.png` | `printf 'alice\n21\n%s\n' $(printf 'B%.0s' {1..60}) \| ./bin/asan/vulnerable_q2_format` (top part up to `SUMMARY:`) | 5.9 Q2 observations (Figure 18) |
| 19 | `19_q2_test_table.png` | `bash tests/scenarios/q2_format.sh` (≈170 columns wide) | 5.8 Q2 test cases (Figure 19) |
| 20 | `20_all_tests_summary.png` | `make test 2>&1 \| tail -11` | 7 Testing and evaluation (Figure 20) |

> Note for #13: run `make all asan` again afterwards, because `make clean`
> removes the other binaries.

## Phase 5 — Analysis and CI

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 22 | `22_cppcheck_before_after.png` | `cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem --suppress=checkersReport -Isrc/lib -q src/vulnerable; echo "---- secure ----"; cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem --suppress=checkersReport -Isrc/lib -q src/secure src/lib tests; echo "exit=$?"` | 6.3 Cppcheck before and after (Figure 22) |
| 23 | `23_banned_api_scan.png` | `python3 analysis/banned_functions.py src/vulnerable; python3 analysis/banned_functions.py src/secure src/lib` | 6.3 Banned-API scan (Figure 23) |
| 24 | `24_analysis_summary.png` | `make analyze 2>&1 \| tail -32` | 6.2 Analysis summary (Figure 24) |
| 25 | `25_ci_github_actions.png` | Browser: GitHub repository → **Actions** → latest **CI** run, all steps green | 8 Continuous integration (Figure 25) |

## 20 additional examples

| # | Filename | Command | Report section |
|---|----------|---------|----------------|
| 26 | `26_examples_test_table.png` | `bash tests/scenarios/examples.sh` (90 rows, ≈170 columns wide — two captures are fine) | 9.3 Examples test run (Figure 26) |
| 27 | `27_examples_demos.png` | `./bin/examples/e13_command_injection/vulnerable 'dave; echo INJECTED'; ./bin/examples/e13_command_injection/secure 'dave; echo INJECTED'; ./bin/examples/e14_path_traversal/vulnerable ../secret.txt; ./bin/examples/e14_path_traversal/secure ../secret.txt` | 9.4 Examples demonstrations (Figure 27) |

## Checklist

- [ ] 01_toolchain_versions.png
- [ ] 02_repo_structure.png
- [ ] 03_make_help.png
- [ ] 04_unit_tests_safe_string.png
- [ ] 05_unit_tests_input_handler.png
- [ ] 06_valgrind_unit_tests.png
- [ ] 07_q1_vuln_normal_vs_overflow.png
- [ ] 08_q1_vuln_segfault.png
- [ ] 09_q1_asan_stack_overflow.png
- [ ] 10_q1_asan_misses_intra_struct.png
- [ ] 11_q1_secure_rejects.png
- [ ] 12_q1_test_table.png
- [ ] 13_q2_gcc_warnings.png
- [ ] 14_q2_vuln_format_leak.png
- [ ] 15_q2_vuln_validation.png
- [ ] 16_q2_vuln_crash.png
- [ ] 17_q2_secure.png
- [ ] 18_q2_asan_record_overflow.png
- [ ] 19_q2_test_table.png
- [ ] 20_all_tests_summary.png
- [ ] 21_q1_valgrind_ret_overwrite.png
- [ ] 22_cppcheck_before_after.png
- [ ] 23_banned_api_scan.png
- [ ] 24_analysis_summary.png
- [ ] 25_ci_github_actions.png
- [ ] 26_examples_test_table.png
- [ ] 27_examples_demos.png
