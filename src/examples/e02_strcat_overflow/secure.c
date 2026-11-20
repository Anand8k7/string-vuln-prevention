/*
 * e02_strcat_overflow  (SECURE)
 * CYE551 Mini Project - example 2 of 20
 *
 * Fix:   safe_concat() takes the TOTAL size of msg, finds the current end
 *        within that size and appends only what fits. Every call is
 *        checked; SS_TRUNCATED means the greeting would not fit -> reject.
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    char msg[24];
    ss_status st;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    st = safe_copy(msg, sizeof msg, "Hello, ");
    if (st == SS_OK) {
        st = safe_concat(msg, sizeof msg, argv[1]);        /* FIX */
    }
    if (st == SS_OK) {
        st = safe_concat(msg, sizeof msg, "!");            /* FIX */
    }
    if (st != SS_OK) {
        fprintf(stderr, "REJECTED: name is too long (greeting max %zu characters)\n",
                sizeof msg - 1);
        return 2;
    }
    puts(msg);
    return 0;
}
