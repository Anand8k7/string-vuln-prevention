/*
 * e15_use_after_free  (SECURE)
 * CYE551 Mini Project - example 15 of 20
 *
 * Fix:   the buffer has ONE owner and ONE place where it is freed, after its
 *        last use; the pointer is set to NULL right after free() so any
 *        later use would be an obvious NULL access instead of silent reuse.
 *        Inputs are validated (name 1-32 chars, command stay|logout).
 * Usage: ./secure <name> <stay|logout>   exit 0 = ok, 2 = rejected
 */
#include "safe_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *user;
    size_t size;
    int logout;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <name> <stay|logout>\n", argv[0]);
        return 1;
    }
    if (validate_input(argv[1], 1, 32, CHARSET_ALNUM, "._-", NULL) != VAL_OK) {
        fprintf(stderr, "REJECTED: name must be 1-32 characters of [A-Za-z0-9._-]\n");
        return 2;
    }
    if (strcmp(argv[2], "logout") != 0 && strcmp(argv[2], "stay") != 0) {
        fprintf(stderr, "REJECTED: command must be 'stay' or 'logout'\n");
        return 2;
    }
    logout = (strcmp(argv[2], "logout") == 0);

    size = strlen(argv[1]) + 1;
    user = malloc(size);
    if (user == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 3;
    }
    (void)safe_copy(user, size, argv[1]);       /* fits: size = len + 1 */

    printf("Goodbye, %s\n", user);              /* FIX: use first ... */
    if (logout) {
        printf("(session closed)\n");
    }
    free(user);                                 /* ... then free once */
    user = NULL;                                /* FIX: no dangling pointer */
    return 0;
}
