/*
 * test_safe_string.c - Unit tests for src/lib/safe_string.c
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Module 5 (Testing & Evaluation)
 *
 * Each test checks three things:
 *   1. the returned status code,
 *   2. the resulting string (content / length / termination),
 *   3. that no byte past the logical buffer size was written (guard bytes).
 * The binary is built with AddressSanitizer + UBSan, so any real
 * out-of-bounds read or write also aborts the run.
 */
#include "safe_string.h"
#include "test_framework.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Text for the Expected/Actual columns: status without the "SS_" prefix,
 * plus the resulting string length. */
static const char *st_txt(char *out, size_t out_size, ss_status st,
                          const char *dst)
{
    if (dst != NULL) {
        snprintf(out, out_size, "%s,len=%zu", ss_status_str(st) + 3,
                 strlen(dst));
    } else {
        snprintf(out, out_size, "%s", ss_status_str(st) + 3);
    }
    return out;
}

/* Area = logical buffer (up to 64 bytes) + guard bytes. */
#define AREA_SIZE (64 + TF_GUARD_LEN)

/* ------------------------------------------------------------------------- */
static void test_safe_strlen(void)
{
    char raw[5] = { 'a', 'b', 'c', 'd', 'e' };   /* NOT terminated */
    char t[TF_TEXT];

    snprintf(t, sizeof t, "%zu", safe_strlen("hello", 100));
    TF_CHECK("SL-01", "Normal", "safe_strlen(\"hello\", 100)", "5", t,
             safe_strlen("hello", 100) == 5);

    snprintf(t, sizeof t, "%zu", safe_strlen(raw, sizeof raw));
    TF_CHECK("SL-02", "Boundary", "unterminated 5-byte array, max=5", "5", t,
             safe_strlen(raw, sizeof raw) == 5);

    snprintf(t, sizeof t, "%zu", safe_strlen(NULL, 10));
    TF_CHECK("SL-03", "Invalid", "NULL pointer", "0", t,
             safe_strlen(NULL, 10) == 0);
}

/* ------------------------------------------------------------------------- */
static void test_safe_copy(void)
{
    char area[AREA_SIZE];
    char big[1001];
    char e[TF_TEXT], a[TF_TEXT];
    ss_status st;

    memset(big, 'A', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    /* Normal */
    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 16, "hello");
    TF_CHECK("SC-01", "Normal", "copy \"hello\" into buf[16]",
             st_txt(e, sizeof e, SS_OK, "hello"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "hello") == 0 && tf_guard_ok(area, 16));

    tf_guard_init(area, sizeof area);
    memcpy(area, "hello", 6);
    st = safe_copy(area, 16, area + 2);          /* overlapping src/dst */
    TF_CHECK("SC-02", "Normal", "overlapping copy (src = dst + 2)",
             st_txt(e, sizeof e, SS_OK, "llo"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "llo") == 0);

    /* Boundary */
    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 8, "abcdefg");          /* 7 chars + '\0' = 8 */
    TF_CHECK("SC-03", "Boundary", "7 chars into buf[8] (exact fit)",
             st_txt(e, sizeof e, SS_OK, "abcdefg"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "abcdefg") == 0 && tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 8, "abcdefgh");         /* one byte too long */
    TF_CHECK("SC-04", "Boundary", "8 chars into buf[8] (one too many)",
             st_txt(e, sizeof e, SS_TRUNCATED, "abcdefg"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strcmp(area, "abcdefg") == 0 &&
             tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 8, "");
    TF_CHECK("SC-05", "Boundary", "empty source string",
             st_txt(e, sizeof e, SS_OK, ""), st_txt(a, sizeof a, st, area),
             st == SS_OK && area[0] == '\0' && tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 1, "a");                /* only room for '\0' */
    TF_CHECK("SC-06", "Boundary", "dst_size = 1 (room for '\\0' only)",
             st_txt(e, sizeof e, SS_TRUNCATED, ""), st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && area[0] == '\0' && tf_guard_ok(area, 1));

    /* Invalid */
    st = safe_copy(NULL, 8, "abc");
    TF_CHECK("SC-07", "Invalid", "dst = NULL",
             st_txt(e, sizeof e, SS_ERR_NULL, NULL), st_txt(a, sizeof a, st, NULL),
             st == SS_ERR_NULL);

    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 8, NULL);
    TF_CHECK("SC-08", "Invalid", "src = NULL (dst becomes \"\")",
             st_txt(e, sizeof e, SS_ERR_NULL, ""), st_txt(a, sizeof a, st, area),
             st == SS_ERR_NULL && area[0] == '\0' && tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 0, "abc");
    TF_CHECK("SC-09", "Invalid", "dst_size = 0 (nothing written)",
             st_txt(e, sizeof e, SS_ERR_SIZE, NULL), st_txt(a, sizeof a, st, NULL),
             st == SS_ERR_SIZE && tf_guard_ok(area, 0));

    {
        int negative = -1;                       /* classic CWE-195 mistake */
        tf_guard_init(area, sizeof area);
        st = safe_copy(area, (size_t)negative, "abc");
        TF_CHECK("SC-10", "Invalid", "dst_size = (size_t)-1 (negative int)",
                 st_txt(e, sizeof e, SS_ERR_SIZE, NULL),
                 st_txt(a, sizeof a, st, NULL),
                 st == SS_ERR_SIZE && tf_guard_ok(area, 0));
    }

    /* Oversized */
    tf_guard_init(area, sizeof area);
    st = safe_copy(area, 16, big);
    TF_CHECK("SC-11", "Oversized", "1000-char string into buf[16]",
             st_txt(e, sizeof e, SS_TRUNCATED, "AAAAAAAAAAAAAAA"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strlen(area) == 15 && tf_guard_ok(area, 16));
}

/* ------------------------------------------------------------------------- */
static void test_safe_concat(void)
{
    char area[AREA_SIZE];
    char big[1001];
    char e[TF_TEXT], a[TF_TEXT];
    ss_status st;
    int i;

    memset(big, 'B', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    /* Normal */
    tf_guard_init(area, sizeof area);
    safe_copy(area, 16, "foo");
    st = safe_concat(area, 16, "bar");
    TF_CHECK("CC-01", "Normal", "\"foo\" + \"bar\" in buf[16]",
             st_txt(e, sizeof e, SS_OK, "foobar"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "foobar") == 0 && tf_guard_ok(area, 16));

    /* Boundary */
    tf_guard_init(area, sizeof area);
    safe_copy(area, 8, "abc");
    st = safe_concat(area, 8, "defg");
    TF_CHECK("CC-02", "Boundary", "\"abc\" + \"defg\" in buf[8] (exact fit)",
             st_txt(e, sizeof e, SS_OK, "abcdefg"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "abcdefg") == 0 && tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    safe_copy(area, 8, "abc");
    st = safe_concat(area, 8, "defgh");
    TF_CHECK("CC-03", "Boundary", "\"abc\" + \"defgh\" in buf[8] (1 over)",
             st_txt(e, sizeof e, SS_TRUNCATED, "abcdefg"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strcmp(area, "abcdefg") == 0 &&
             tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    safe_copy(area, 8, "abcdefg");
    st = safe_concat(area, 8, "x");
    TF_CHECK("CC-04", "Boundary", "append to an already full buffer",
             st_txt(e, sizeof e, SS_TRUNCATED, "abcdefg"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strcmp(area, "abcdefg") == 0 &&
             tf_guard_ok(area, 8));

    /* Invalid */
    tf_guard_init(area, sizeof area);              /* no '\0' anywhere */
    st = safe_concat(area, 8, "x");
    TF_CHECK("CC-05", "Invalid", "dst not terminated within dst_size",
             st_txt(e, sizeof e, SS_ERR_UNTERMINATED, "ZZZZZZZ"),
             st_txt(a, sizeof a, st, area),
             st == SS_ERR_UNTERMINATED && strlen(area) == 7 &&
             tf_guard_ok(area, 8));

    tf_guard_init(area, sizeof area);
    safe_copy(area, 8, "abc");
    st = safe_concat(area, 8, NULL);
    TF_CHECK("CC-06", "Invalid", "src = NULL (dst unchanged)",
             st_txt(e, sizeof e, SS_ERR_NULL, "abc"), st_txt(a, sizeof a, st, area),
             st == SS_ERR_NULL && strcmp(area, "abc") == 0);

    st = safe_concat(area, 0, "x");
    TF_CHECK("CC-07", "Invalid", "dst_size = 0",
             st_txt(e, sizeof e, SS_ERR_SIZE, NULL), st_txt(a, sizeof a, st, NULL),
             st == SS_ERR_SIZE);

    /* Oversized */
    tf_guard_init(area, sizeof area);
    safe_copy(area, 16, "hi");
    st = safe_concat(area, 16, big);
    TF_CHECK("CC-08", "Oversized", "\"hi\" + 1000-char string in buf[16]",
             st_txt(e, sizeof e, SS_TRUNCATED, "hiBBBBBBBBBBBBB"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strlen(area) == 15 && tf_guard_ok(area, 16));

    /* The classic "strcat in a loop" bug: 100 appends into buf[16]. */
    tf_guard_init(area, sizeof area);
    area[0] = '\0';
    st = SS_OK;
    for (i = 0; i < 100; i++) {
        st = safe_concat(area, 16, "ab");
    }
    TF_CHECK("CC-09", "Oversized", "100 x append \"ab\" into buf[16]",
             st_txt(e, sizeof e, SS_TRUNCATED, "abababababababa"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strlen(area) == 15 && tf_guard_ok(area, 16));
}

/* ------------------------------------------------------------------------- */
static void test_safe_format(void)
{
    char area[AREA_SIZE];
    char big[1001];
    char e[TF_TEXT], a[TF_TEXT];
    ss_status st;

    memset(big, 'C', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    /* Normal */
    tf_guard_init(area, sizeof area);
    st = safe_format(area, 16, "%s-%d", "id", 42);
    TF_CHECK("SF-01", "Normal", "format \"%s-%d\" -> \"id-42\"",
             st_txt(e, sizeof e, SS_OK, "id-42"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "id-42") == 0 && tf_guard_ok(area, 16));

    /* User text containing format specifiers is passed as DATA via "%s",
     * so it is printed literally and never interpreted. */
    tf_guard_init(area, sizeof area);
    st = safe_format(area, 16, "%s", "%x%x%n");
    TF_CHECK("SF-02", "Normal", "user text \"%x%x%n\" printed literally",
             st_txt(e, sizeof e, SS_OK, "%x%x%n"), st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "%x%x%n") == 0 && tf_guard_ok(area, 16));

    /* Boundary */
    tf_guard_init(area, sizeof area);
    st = safe_format(area, 12, "%d", INT_MIN);   /* "-2147483648" = 11 chars */
    TF_CHECK("SF-03", "Boundary", "INT_MIN into buf[12] (exact fit)",
             st_txt(e, sizeof e, SS_OK, "-2147483648"),
             st_txt(a, sizeof a, st, area),
             st == SS_OK && strcmp(area, "-2147483648") == 0 &&
             tf_guard_ok(area, 12));

    tf_guard_init(area, sizeof area);
    st = safe_format(area, 11, "%d", INT_MIN);
    TF_CHECK("SF-04", "Boundary", "INT_MIN into buf[11] (one too small)",
             st_txt(e, sizeof e, SS_TRUNCATED, "-214748364"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strcmp(area, "-214748364") == 0 &&
             tf_guard_ok(area, 11));

    /* Invalid */
    {
        const char *null_fmt = NULL;
        tf_guard_init(area, sizeof area);
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
        st = safe_format(area, 16, null_fmt);    /* deliberately bad call */
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
        TF_CHECK("SF-05", "Invalid", "format string = NULL",
                 st_txt(e, sizeof e, SS_ERR_NULL, ""),
                 st_txt(a, sizeof a, st, area),
                 st == SS_ERR_NULL && area[0] == '\0' && tf_guard_ok(area, 16));
    }

    st = safe_format(NULL, 16, "%s", "x");
    TF_CHECK("SF-06", "Invalid", "dst = NULL",
             st_txt(e, sizeof e, SS_ERR_NULL, NULL), st_txt(a, sizeof a, st, NULL),
             st == SS_ERR_NULL);

    /* Oversized */
    tf_guard_init(area, sizeof area);
    st = safe_format(area, 16, "Hello %s!", big);
    TF_CHECK("SF-07", "Oversized", "\"Hello %s!\" with 1000-char name",
             st_txt(e, sizeof e, SS_TRUNCATED, "Hello CCCCCCCCC"),
             st_txt(a, sizeof a, st, area),
             st == SS_TRUNCATED && strlen(area) == 15 && tf_guard_ok(area, 16));
}

/* ------------------------------------------------------------------------- */
static void test_validate_input(void)
{
    char big[10001];
    char *unterminated;
    size_t pos = 0;
    char e[TF_TEXT], a[TF_TEXT];
    val_status v;

    memset(big, 'a', sizeof big - 1);
    big[sizeof big - 1] = '\0';

#define VTXT(buf, st) (snprintf((buf), sizeof(buf), "%s", val_status_str(st) + 4), (buf))

    /* Normal */
    v = validate_input("alice99", 1, 16, CHARSET_ALNUM, NULL, NULL);
    TF_CHECK("VI-01", "Normal", "\"alice99\" alnum, len 1..16",
             VTXT(e, VAL_OK), VTXT(a, v), v == VAL_OK);

    v = validate_input("John Smith", 1, 32, CHARSET_ALPHA | CHARSET_SPACE,
                       NULL, NULL);
    TF_CHECK("VI-02", "Normal", "\"John Smith\" alpha+space",
             VTXT(e, VAL_OK), VTXT(a, v), v == VAL_OK);

    v = validate_input("a.b-c_d", 1, 16, CHARSET_ALNUM, "._-", NULL);
    TF_CHECK("VI-03", "Normal", "\"a.b-c_d\" with extra \"._-\"",
             VTXT(e, VAL_OK), VTXT(a, v), v == VAL_OK);

    /* Boundary */
    v = validate_input("abcdefghijklmnop", 1, 16, CHARSET_ALPHA, NULL, NULL);
    TF_CHECK("VI-04", "Boundary", "length == max_len (16)",
             VTXT(e, VAL_OK), VTXT(a, v), v == VAL_OK);

    v = validate_input("abcdefghijklmnopq", 1, 16, CHARSET_ALPHA, NULL, NULL);
    TF_CHECK("VI-05", "Boundary", "length == max_len + 1 (17)",
             VTXT(e, VAL_ERR_TOO_LONG), VTXT(a, v), v == VAL_ERR_TOO_LONG);

    v = validate_input("", 1, 16, CHARSET_ALPHA, NULL, NULL);
    TF_CHECK("VI-06", "Boundary", "empty string, min_len 1",
             VTXT(e, VAL_ERR_EMPTY), VTXT(a, v), v == VAL_ERR_EMPTY);

    /* Invalid */
    v = validate_input("bob;rm", 1, 16, CHARSET_ALNUM, NULL, &pos);
    snprintf(a, sizeof a, "%s@%zu", val_status_str(v) + 4, pos);
    TF_CHECK("VI-07", "Invalid", "\"bob;rm\" (';' not allowed)",
             "ERR_BAD_CHAR@3", a, v == VAL_ERR_BAD_CHAR && pos == 3);

    v = validate_input("%s%n", 1, 16, CHARSET_ALNUM, NULL, &pos);
    snprintf(a, sizeof a, "%s@%zu", val_status_str(v) + 4, pos);
    TF_CHECK("VI-08", "Invalid", "format specifiers \"%s%n\"",
             "ERR_BAD_CHAR@0", a, v == VAL_ERR_BAD_CHAR && pos == 0);

    v = validate_input("abc\tdef", 1, 16, CHARSET_ALPHA | CHARSET_SPACE,
                       NULL, &pos);
    snprintf(a, sizeof a, "%s@%zu", val_status_str(v) + 4, pos);
    TF_CHECK("VI-09", "Invalid", "control character (TAB)",
             "ERR_BAD_CHAR@3", a, v == VAL_ERR_BAD_CHAR && pos == 3);

    v = validate_input("caf\xc3\xa9", 1, 16, CHARSET_ALPHA, NULL, &pos);
    snprintf(a, sizeof a, "%s@%zu", val_status_str(v) + 4, pos);
    TF_CHECK("VI-10", "Invalid", "non-ASCII UTF-8 byte",
             "ERR_BAD_CHAR@3", a, v == VAL_ERR_BAD_CHAR && pos == 3);

    v = validate_input(NULL, 1, 16, CHARSET_ALPHA, NULL, NULL);
    TF_CHECK("VI-11", "Invalid", "NULL input",
             VTXT(e, VAL_ERR_NULL), VTXT(a, v), v == VAL_ERR_NULL);

    /* Oversized */
    v = validate_input(big, 1, 16, CHARSET_ALPHA, NULL, NULL);
    TF_CHECK("VI-12", "Oversized", "10000-char string, max_len 16",
             VTXT(e, VAL_ERR_TOO_LONG), VTXT(a, v), v == VAL_ERR_TOO_LONG);

    /* Heap buffer of exactly 17 bytes with NO terminator. A plain strlen()
     * would read past the end (ASan would abort). validate_input only reads
     * max_len + 1 = 17 bytes, so this is safe. */
    unterminated = malloc(17);
    if (unterminated != NULL) {
        memset(unterminated, 'a', 17);
        v = validate_input(unterminated, 1, 16, CHARSET_ALPHA, NULL, NULL);
        free(unterminated);
    } else {
        v = VAL_ERR_NULL;
    }
    TF_CHECK("VI-13", "Oversized", "unterminated 17-byte heap buffer",
             VTXT(e, VAL_ERR_TOO_LONG), VTXT(a, v), v == VAL_ERR_TOO_LONG);
}

/* ------------------------------------------------------------------------- */
static void test_validate_integer(void)
{
    char e[TF_TEXT], a[TF_TEXT];
    long out = 0;
    val_status v;

    /* Normal */
    v = validate_integer("42", 0, 150, &out);
    snprintf(a, sizeof a, "%s,%ld", val_status_str(v) + 4, out);
    TF_CHECK("VN-01", "Normal", "\"42\" in [0,150]", "OK,42", a,
             v == VAL_OK && out == 42);

    v = validate_integer("-5", -10, 10, &out);
    snprintf(a, sizeof a, "%s,%ld", val_status_str(v) + 4, out);
    TF_CHECK("VN-02", "Normal", "\"-5\" in [-10,10]", "OK,-5", a,
             v == VAL_OK && out == -5);

    /* Boundary */
    v = validate_integer("0", 0, 150, &out);
    snprintf(a, sizeof a, "%s,%ld", val_status_str(v) + 4, out);
    TF_CHECK("VN-03", "Boundary", "\"0\" = min", "OK,0", a,
             v == VAL_OK && out == 0);

    v = validate_integer("150", 0, 150, &out);
    snprintf(a, sizeof a, "%s,%ld", val_status_str(v) + 4, out);
    TF_CHECK("VN-04", "Boundary", "\"150\" = max", "OK,150", a,
             v == VAL_OK && out == 150);

    v = validate_integer("151", 0, 150, &out);
    TF_CHECK("VN-05", "Boundary", "\"151\" = max + 1",
             VTXT(e, VAL_ERR_RANGE), VTXT(a, v), v == VAL_ERR_RANGE);

    v = validate_integer("-1", 0, 150, &out);
    TF_CHECK("VN-06", "Boundary", "\"-1\" = min - 1",
             VTXT(e, VAL_ERR_RANGE), VTXT(a, v), v == VAL_ERR_RANGE);

    /* Invalid */
    v = validate_integer("", 0, 150, &out);
    TF_CHECK("VN-07", "Invalid", "empty string",
             VTXT(e, VAL_ERR_EMPTY), VTXT(a, v), v == VAL_ERR_EMPTY);

    v = validate_integer("12a", 0, 150, &out);
    TF_CHECK("VN-08", "Invalid", "\"12a\" (trailing junk)",
             VTXT(e, VAL_ERR_NOT_NUMBER), VTXT(a, v), v == VAL_ERR_NOT_NUMBER);

    v = validate_integer(" 42", 0, 150, &out);
    TF_CHECK("VN-09", "Invalid", "\" 42\" (leading space)",
             VTXT(e, VAL_ERR_NOT_NUMBER), VTXT(a, v), v == VAL_ERR_NOT_NUMBER);

    v = validate_integer("+42", 0, 150, &out);
    TF_CHECK("VN-10", "Invalid", "\"+42\" (plus sign)",
             VTXT(e, VAL_ERR_NOT_NUMBER), VTXT(a, v), v == VAL_ERR_NOT_NUMBER);

    v = validate_integer("-", 0, 150, &out);
    TF_CHECK("VN-11", "Invalid", "\"-\" (sign only)",
             VTXT(e, VAL_ERR_NOT_NUMBER), VTXT(a, v), v == VAL_ERR_NOT_NUMBER);

    /* Oversized */
    v = validate_integer("99999999999999999999999", LONG_MIN, LONG_MAX, &out);
    TF_CHECK("VN-12", "Oversized", "23-digit number (overflows long)",
             VTXT(e, VAL_ERR_RANGE), VTXT(a, v), v == VAL_ERR_RANGE);

#undef VTXT
}

int main(void)
{
    test_safe_strlen();
    test_safe_copy();
    test_safe_concat();
    test_safe_format();
    test_validate_input();
    test_validate_integer();
    return tf_report("safe_string");
}
