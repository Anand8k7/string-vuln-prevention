/*
 * q2_format.c  (SECURE VERSION)
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Q2: Improper input validation + unsafe formatting
 *     -> fgets, whitelist validation, strict number parsing, snprintf,
 *        fixed format strings
 *
 * Same feedback form as src/vulnerable/q2_format.c (Name, Age, Message on
 * standard input, one per line) but following the project workflow:
 *
 *   [1] User Input          input_read_line()  fgets-based, bounded, drains
 *                                              over-long lines, rejects NUL
 *   [2] Input Validation    validate_input() / validate_integer()
 *   [3] Length & Boundary   IN_TOO_LONG / SS_TRUNCATED => reject
 *   [4] Safe String Ops     safe_format() (vsnprintf) for the record
 *   [5] Output Verification record terminated and has the expected length
 *   [6] Result              printed ONLY through fixed format strings
 *
 * Fixes for the vulnerable version:
 *   [B1] scanf("%s")          -> input_read_line (fgets) + length limit;
 *                               whole line is read, so "John Smith" works
 *   [B2] scanf("%d") unchecked-> validate_integer: digits only, 1..120,
 *                               overflow detected, every result checked
 *   [B3] sprintf(record, ...) -> safe_format, SS_TRUNCATED rejected
 *   [B4] printf(msg)          -> printf("%s", msg): user text is DATA, never
 *                               a format. '%' is deliberately ALLOWED in the
 *                               message ("50% off") to show that the fixed
 *                               format string alone neutralises "%p", "%n".
 *
 * Exit codes: 0 = success, 2 = input rejected, 3 = internal check failed.
 */
#include "input_handler.h"
#include "safe_string.h"

#include <stdio.h>
#include <string.h>

#define NAME_SIZE   16
#define MSG_SIZE    41          /* message: at most 40 characters */
#define RECORD_SIZE 64
#define AGE_SIZE    8           /* "120" fits easily; longer = invalid */

#define NAME_MAX_LEN (NAME_SIZE - 1)
#define MSG_MAX_LEN  (MSG_SIZE - 1)
#define AGE_MIN      1
#define AGE_MAX      120

/* Whitelists (letters/digits/space come from the CHARSET_* flags). */
#define NAME_EXTRA "-.'"
#define MSG_EXTRA  ".,!?'%-:()/$"

static int reject(const char *field, const char *reason)
{
    /* Fixed format string: field and reason are only ever %s arguments. */
    fprintf(stderr, "REJECTED: %s %s\n", field, reason);
    return 2;
}

/* [1] Read one line; translate input-layer problems into rejections.
 * Returns 0 on success, otherwise the exit code to use. */
static int read_field(const char *prompt, const char *field,
                      char *buf, size_t buf_size, size_t max_len)
{
    char msg[64];
    in_status in;

    printf("%s", prompt);
    fflush(stdout);

    in = input_read_line(stdin, buf, buf_size, NULL);
    switch (in) {
    case IN_OK:
        return 0;
    case IN_TOO_LONG:
        (void)safe_format(msg, sizeof msg, "is too long (max %zu characters)",
                          max_len);
        return reject(field, msg);
    case IN_EOF:
        return reject(field, "is missing (end of input)");
    case IN_ERR_NUL_BYTE:
        return reject(field, "contains a NUL byte");
    default:
        return reject(field, in_status_str(in));
    }
}

static int reject_validation(const char *field, val_status v, size_t pos,
                             size_t max_len)
{
    char msg[64];

    switch (v) {
    case VAL_ERR_TOO_LONG:
        (void)safe_format(msg, sizeof msg, "is too long (max %zu characters)",
                          max_len);
        break;
    case VAL_ERR_EMPTY:
        (void)safe_format(msg, sizeof msg, "must not be empty");
        break;
    case VAL_ERR_BAD_CHAR:
        (void)safe_format(msg, sizeof msg,
                          "contains a character that is not allowed "
                          "(position %zu)", pos);
        break;
    case VAL_ERR_NOT_NUMBER:
        (void)safe_format(msg, sizeof msg, "is not a whole number");
        break;
    case VAL_ERR_RANGE:
        (void)safe_format(msg, sizeof msg, "is out of range (%d-%d)",
                          AGE_MIN, AGE_MAX);
        break;
    default:
        (void)safe_format(msg, sizeof msg, "is invalid (%s)",
                          val_status_str(v));
        break;
    }
    return reject(field, msg);
}

int main(void)
{
    /* Same simulated secret as the vulnerable version: it must never
     * appear in the output, whatever the user types. */
    volatile unsigned long secret_token = 0x5EC12E7AB1EUL;
    char name[NAME_SIZE];
    char age_in[AGE_SIZE];
    char msg[MSG_SIZE];
    char record[RECORD_SIZE];
    long age = 0;
    size_t bad_pos = 0;
    val_status v;
    ss_status st;
    int rc;

    /* ---- [1] User Input (bounded, line based) ------------------------- */
    rc = read_field("Name: ", "name", name, sizeof name, NAME_MAX_LEN);
    if (rc != 0) {
        return rc;
    }
    rc = read_field("Age: ", "age", age_in, sizeof age_in, 3);
    if (rc != 0) {
        return rc;
    }
    rc = read_field("Message: ", "message", msg, sizeof msg, MSG_MAX_LEN);
    if (rc != 0) {
        return rc;
    }
    printf("\n");

    /* ---- [2] Input Validation ----------------------------------------- */
    v = validate_input(name, 1, NAME_MAX_LEN, CHARSET_ALPHA | CHARSET_SPACE,
                       NAME_EXTRA, &bad_pos);
    if (v != VAL_OK) {
        return reject_validation("name", v, bad_pos, NAME_MAX_LEN);
    }

    v = validate_integer(age_in, AGE_MIN, AGE_MAX, &age);
    if (v != VAL_OK) {
        return reject_validation("age", v, 0, 3);
    }

    v = validate_input(msg, 1, MSG_MAX_LEN, CHARSET_ALNUM | CHARSET_SPACE,
                       MSG_EXTRA, &bad_pos);
    if (v != VAL_OK) {
        return reject_validation("message", v, bad_pos, MSG_MAX_LEN);
    }

    /* ---- [3]+[4] Bounded formatting ----------------------------------- */
    st = safe_format(record, sizeof record, "name=%s age=%ld msg=%s",
                     name, age, msg);
    if (st != SS_OK) {
        char why[64];
        (void)safe_format(why, sizeof why, "would exceed %d characters (%s)",
                          RECORD_SIZE - 1, ss_status_str(st));
        return reject("record", why);
    }

    /* ---- [5] Output Verification -------------------------------------- */
    if (safe_strlen(record, sizeof record) >= sizeof record ||
        strncmp(record, "name=", 5) != 0) {
        fprintf(stderr, "INTERNAL ERROR: output verification failed\n");
        return 3;
    }

    /* ---- [6] Result: fixed format strings only ------------------------ */
    printf("Your message: %s\n", msg);       /* was: printf(msg) */
    printf("Saved record: %s\n", record);

    (void)secret_token;
    return 0;
}
