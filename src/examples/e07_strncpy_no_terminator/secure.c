/*
 * e07_strncpy_no_terminator  (SECURE)
 * CYE551 Mini Project - example 7 of 20
 *
 * Fix:   safe_copy() always terminates and reports truncation, which is
 *        rejected. (If strncpy must be used, the minimum fix is
 *            strncpy(name, src, sizeof name - 1);
 *            name[sizeof name - 1] = '\0';
 *        plus a separate length check, because strncpy cannot report
 *        truncation.)
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char name[8];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    if (safe_copy(name, sizeof name, argv[1]) != SS_OK) {   /* FIX */
        fprintf(stderr, "REJECTED: name is too long (max %zu characters)\n",
                sizeof name - 1);
        return 2;
    }
    printf("name=%s len=%zu\n", name, strlen(name));
    return 0;
}
