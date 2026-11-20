/*
 * e13_command_injection  (SECURE)
 * CYE551 Mini Project - example 13 of 20
 *
 * Fix:   1. No shell at all: the greeting is printed by the program itself.
 *           (If an external program is really needed, use fork()+execv()
 *           with an argument ARRAY - never system() or popen() with a
 *           command line built from user input.)
 *        2. Whitelist validation: letters, digits and ._- only, 1-32 chars,
 *           so shell metacharacters are rejected anyway.
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    size_t pos = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    if (validate_input(argv[1], 1, 32, CHARSET_ALNUM, "._-", &pos) != VAL_OK) {
        fprintf(stderr, "REJECTED: name must be 1-32 characters of "
                        "[A-Za-z0-9._-]\n");
        return 2;
    }
    printf("Hello, %s\n", argv[1]);             /* FIX: no system() */
    return 0;
}
