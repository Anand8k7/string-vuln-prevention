/*
 * e20_strtok_reentrancy  (SECURE)
 * CYE551 Mini Project - example 20 of 20
 *
 * Fix:   strtok_r() (POSIX) keeps its position in a variable owned by the
 *        caller, so the outer and inner loops each have their own save
 *        pointer. The input is also validated (length, allowed characters)
 *        and every pair must have exactly one non-empty key and value.
 * Usage: ./secure "a=1,b=2,c=3"     exit 0 = ok, 2 = rejected, 1 = usage
 */
#define _POSIX_C_SOURCE 200809L     /* strtok_r() */

#include "safe_string.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[128];
    char *outer_save = NULL, *inner_save = NULL;
    char *pair;
    size_t count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key=value,...>\n", argv[0]);
        return 1;
    }
    if (validate_input(argv[1], 1, sizeof buf - 1, CHARSET_ALNUM, "=,_-.",
                       NULL) != VAL_OK ||
        safe_copy(buf, sizeof buf, argv[1]) != SS_OK) {
        fprintf(stderr, "REJECTED: input must be 1-%zu characters of "
                        "[A-Za-z0-9=,_-.]\n", sizeof buf - 1);
        return 2;
    }
    for (pair = strtok_r(buf, ",", &outer_save); pair != NULL;
         pair = strtok_r(NULL, ",", &outer_save)) {
        const char *eq = strchr(pair, '=');
        const char *key, *value;

        if (eq == NULL || eq == pair || eq[1] == '\0' ||
            strchr(eq + 1, '=') != NULL) {      /* exactly one '=', both sides */
            fprintf(stderr, "REJECTED: every item must look like key=value\n");
            return 2;
        }
        key = strtok_r(pair, "=", &inner_save);           /* FIX: own state */
        value = strtok_r(NULL, "=", &inner_save);
        if (key == NULL || value == NULL) {
            fprintf(stderr, "REJECTED: every item must look like key=value\n");
            return 2;
        }
        printf("%s = %s\n", key, value);
        count++;
    }
    if (count == 0) {
        fprintf(stderr, "REJECTED: no key=value pairs found\n");
        return 2;
    }
    return 0;
}
