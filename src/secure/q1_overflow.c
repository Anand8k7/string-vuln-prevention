/*
 * q1_overflow.c  (SECURE VERSION)
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Q1: Buffer overflow through strcpy / strcat  ->  bounded copy/concat + checks
 *
 * Same program as src/vulnerable/q1_overflow.c:
 *     ./q1_overflow <username> <department>
 * but every step follows the project workflow:
 *
 *   [1] User Input          input_from_arg()   bounded copy of argv
 *   [2] Input Validation    validate_input()   whitelist + length rules
 *   [3] Length & Boundary   status codes checked; truncation = reject
 *   [4] Safe String Ops     safe_copy() / safe_concat() / safe_format()
 *   [5] Output Verification role unchanged, results terminated & in bounds
 *   [6] Result              print, or reject with a clear error message
 *
 * Fixes for the vulnerable version:
 *   [B1] strcpy(acct.username, argv[1]) -> input_from_arg + validate_input
 *        (1..15 chars) + safe_copy                       (CWE-120/787/193)
 *   [B2] strcat into greeting           -> safe_format, SS_TRUNCATED rejected
 *   [B3] strcpy/strcat chain into path  -> safe_copy + safe_concat, every
 *        status checked, SS_TRUNCATED rejected            (CWE-121)
 *   [B4] no validation                  -> whitelist validation (CWE-20)
 *
 * Exit codes: 0 = success, 1 = usage error, 2 = input rejected,
 *             3 = internal check failed (should never happen).
 */
#include "input_handler.h"
#include "safe_string.h"

#include <stdio.h>
#include <string.h>

#define NAME_SIZE 16
#define ROLE_SIZE 16
#define MSG_SIZE  32
#define PATH_SIZE 32

/* Allowed input. Max length is buffer size - 1 (room for '\0'). */
#define NAME_MAX_LEN   (NAME_SIZE - 1)
#define NAME_EXTRA     "._-"            /* plus letters and digits */
#define DEPT_MAX_LEN   15

struct account {
    char username[NAME_SIZE];
    char role[ROLE_SIZE];
};

/* Print a rejection message and return the "rejected" exit code. */
static int reject(const char *field, const char *reason)
{
    fprintf(stderr, "REJECTED: %s %s\n", field, reason);
    return 2;
}

/* Explain a validation failure in words. */
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
    default:
        (void)safe_format(msg, sizeof msg, "is invalid (%s)",
                          val_status_str(v));
        break;
    }
    return reject(field, msg);
}

int main(int argc, char *argv[])
{
    struct account acct;
    char name_in[NAME_SIZE];       /* raw input, bounded */
    char dept_in[DEPT_MAX_LEN + 1];
    char greeting[MSG_SIZE];
    char path[PATH_SIZE];
    size_t bad_pos = 0;
    in_status in;
    val_status v;
    ss_status st;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <department>\n",
                (argc > 0 && argv[0] != NULL) ? argv[0] : "q1_overflow");
        return 1;
    }

    /* The role is set first, exactly like the vulnerable version; step [5]
     * checks that nothing changed it. */
    st = safe_copy(acct.role, sizeof acct.role, "guest");
    if (st != SS_OK) {
        return 3;
    }

    /* ---- [1] User Input: bounded copies of argv ----------------------- */
    in = input_from_arg(argc, argv, 1, name_in, sizeof name_in);
    if (in == IN_TOO_LONG) {
        return reject("username", "is too long (max 15 characters)");
    }
    if (in != IN_OK) {
        return reject("username", in_status_str(in));
    }
    in = input_from_arg(argc, argv, 2, dept_in, sizeof dept_in);
    if (in == IN_TOO_LONG) {
        return reject("department", "is too long (max 15 characters)");
    }
    if (in != IN_OK) {
        return reject("department", in_status_str(in));
    }

    /* ---- [2] Input Validation: whitelist + length --------------------- */
    v = validate_input(name_in, 1, NAME_MAX_LEN, CHARSET_ALNUM, NAME_EXTRA,
                       &bad_pos);
    if (v != VAL_OK) {
        return reject_validation("username", v, bad_pos, NAME_MAX_LEN);
    }
    v = validate_input(dept_in, 1, DEPT_MAX_LEN, CHARSET_ALPHA, NULL,
                       &bad_pos);
    if (v != VAL_OK) {
        return reject_validation("department", v, bad_pos, DEPT_MAX_LEN);
    }

    /* ---- [3]+[4] Length checks + safe string operations --------------- */
    /* Every call reports SS_TRUNCATED instead of overflowing; any status
     * other than SS_OK means the result would not fit, so we reject. */
    st = safe_copy(acct.username, sizeof acct.username, name_in);
    if (st != SS_OK) {
        return reject("username", "does not fit in the account record");
    }

    st = safe_format(greeting, sizeof greeting, "Welcome, %s!", acct.username);
    if (st != SS_OK) {
        return reject("greeting", "would not fit in the message buffer");
    }

    st = safe_copy(path, sizeof path, "/home/");
    if (st == SS_OK) {
        st = safe_concat(path, sizeof path, dept_in);
    }
    if (st == SS_OK) {
        st = safe_concat(path, sizeof path, "/");
    }
    if (st == SS_OK) {
        st = safe_concat(path, sizeof path, acct.username);
    }
    if (st != SS_OK) {
        char msg[64];
        (void)safe_format(msg, sizeof msg,
                          "would exceed %d characters (%s)",
                          PATH_SIZE - 1, ss_status_str(st));
        return reject("home directory path", msg);
    }

    /* ---- [5] Output Verification -------------------------------------- */
    /* Defence in depth: confirm that no buffer is unterminated and that the
     * neighbouring field (role) was not modified. */
    if (safe_strlen(acct.username, sizeof acct.username) >= sizeof acct.username ||
        safe_strlen(greeting, sizeof greeting) >= sizeof greeting ||
        safe_strlen(path, sizeof path) >= sizeof path ||
        safe_strlen(acct.role, sizeof acct.role) >= sizeof acct.role ||
        strcmp(acct.role, "guest") != 0) {
        fprintf(stderr, "INTERNAL ERROR: output verification failed\n");
        return 3;
    }

    /* ---- [6] Result --------------------------------------------------- */
    /* Fixed format strings: user data is only ever passed as "%s" args. */
    printf("%s\n", greeting);
    printf("Username : %s\n", acct.username);
    printf("Role     : %s\n", acct.role);
    printf("Home dir : %s\n", path);
    return 0;
}
