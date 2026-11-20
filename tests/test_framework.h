/*
 * test_framework.h - Minimal test framework that prints a PASS/FAIL table
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Module 5 (Testing & Evaluation)
 *
 * Usage:
 *     TF_CHECK("SC-01", "Normal", "copy short string", "SS_OK",
 *              ss_status_str(st), st == SS_OK && strcmp(buf, "hi") == 0);
 *     ...
 *     return tf_report("safe_copy");
 *
 * Every test has an ID, a category (Normal / Boundary / Invalid / Oversized),
 * a short description, the expected and actual result as text, and a pass
 * condition. tf_report() prints the table and returns the process exit code
 * (0 = all passed).
 *
 * Test binaries are compiled with AddressSanitizer, so any out-of-bounds
 * access inside the library aborts the run even if the table says PASS.
 */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

#define TF_MAX_TESTS 256
#define TF_TEXT      40

typedef struct {
    const char *id;
    const char *category;
    const char *desc;
    char expected[TF_TEXT];
    char actual[TF_TEXT];
    int pass;
} tf_result;

static tf_result tf_results[TF_MAX_TESTS];
static int tf_count;

/* Copy a label into a fixed field (the tests also must not overflow!). */
static void tf_set(char *dst, const char *src)
{
    snprintf(dst, TF_TEXT, "%s", src ? src : "(null)");
}

static void tf_record(const char *id, const char *category, const char *desc,
                      const char *expected, const char *actual, int pass)
{
    tf_result *r;

    if (tf_count >= TF_MAX_TESTS) {
        fprintf(stderr, "test_framework: too many tests\n");
        return;
    }
    r = &tf_results[tf_count++];
    r->id = id;
    r->category = category;
    r->desc = desc;
    tf_set(r->expected, expected);
    tf_set(r->actual, actual);
    r->pass = pass ? 1 : 0;
}

#define TF_CHECK(id, cat, desc, expected, actual, cond) \
    tf_record((id), (cat), (desc), (expected), (actual), (cond))

static void tf_line(void)
{
    printf("+--------+-----------+------------------------------------------"
           "+--------------------------+--------------------------+--------+\n");
}

/* Print the table for this suite; return 0 if every test passed. */
static int tf_report(const char *suite)
{
    int i;
    int passed = 0;

    printf("\n=== Test suite: %s ===\n", suite);
    tf_line();
    printf("| %-6s | %-9s | %-40s | %-24s | %-24s | %-6s |\n",
           "ID", "Category", "Description", "Expected", "Actual", "Result");
    tf_line();
    for (i = 0; i < tf_count; i++) {
        const tf_result *r = &tf_results[i];
        /* %.Ns precision keeps every column bounded. */
        printf("| %-6.6s | %-9.9s | %-40.40s | %-24.24s | %-24.24s | %-6s |\n",
               r->id, r->category, r->desc, r->expected, r->actual,
               r->pass ? "PASS" : "FAIL");
        passed += r->pass;
    }
    tf_line();
    printf("Summary [%s]: %d/%d passed, %d failed\n",
           suite, passed, tf_count, tf_count - passed);
    /* Machine-readable line for tests/run_tests.sh */
    printf("TF_RESULT %s %d %d\n", suite, passed, tf_count);

    return (passed == tf_count) ? 0 : 1;
}

/* ------------------------------------------------------------------------- */
/* Guard-byte helpers: detect writes past the logical end of a buffer.        */
/* The test buffer is bigger than the size passed to the function; the extra  */
/* bytes are filled with a pattern and must be unchanged afterwards.          */
/* ------------------------------------------------------------------------- */
#define TF_GUARD_LEN  16
#define TF_GUARD_BYTE ((char)0x5A)

static void tf_guard_init(char *area, size_t area_size)
{
    memset(area, TF_GUARD_BYTE, area_size);
}

/* 1 if bytes [logical_size, logical_size + TF_GUARD_LEN) are untouched. */
static int tf_guard_ok(const char *area, size_t logical_size)
{
    size_t i;
    for (i = 0; i < TF_GUARD_LEN; i++) {
        if (area[logical_size + i] != TF_GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

#endif /* TEST_FRAMEWORK_H */
