/*
 * e01_strcpy_overflow  (SECURE)
 * CYE551 Mini Project - example 1 of 20
 *
 * Fix:   safe_copy() is given sizeof(name), never writes past it, always
 *        terminates, and reports truncation. Truncation = reject.
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    char name[16];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    if (safe_copy(name, sizeof name, argv[1]) != SS_OK) {   /* FIX */
        fprintf(stderr, "REJECTED: name is too long (max %zu characters)\n",
                sizeof name - 1);
        return 2;
    }
    printf("Hello, %s\n", name);
    return 0;
}
