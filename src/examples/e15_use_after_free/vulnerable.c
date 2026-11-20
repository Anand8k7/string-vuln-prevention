/*
 * e15_use_after_free  (VULNERABLE)
 * CYE551 Mini Project - example 15 of 20
 *
 * Bug:   on "logout" the user's name is freed, but the goodbye message
 *        still reads it afterwards. The memory may already have been
 *        reused by the allocator, so the output is garbage (or worse).
 * CWE:   CWE-416 (Use After Free)
 * Usage: ./vulnerable <name> <stay|logout>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#define _POSIX_C_SOURCE 200809L     /* strdup() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *user;
    int logout;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <name> <stay|logout>\n", argv[0]);
        return 1;
    }
    user = strdup(argv[1]);
    if (user == NULL) {
        return 1;
    }
    logout = (strcmp(argv[2], "logout") == 0);
    if (logout) {
        free(user);                     /* session ends here ...         */
    }
    printf("Goodbye, %s\n", user);      /* BUG: ... but user is still used */
    if (!logout) {
        free(user);
    }
    return 0;
}
