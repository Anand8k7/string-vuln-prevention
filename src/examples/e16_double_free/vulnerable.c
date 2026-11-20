/*
 * e16_double_free  (VULNERABLE)
 * CYE551 Mini Project - example 16 of 20
 *
 * Bug:   the error path frees the buffer, and the common clean-up code at
 *        the end frees it AGAIN. Freeing the same pointer twice corrupts
 *        the allocator's internal lists (glibc usually aborts).
 * CWE:   CWE-415 (Double Free)
 * Usage: ./vulnerable <name>      (a name of 32+ characters hits the bug)
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *buf;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    buf = malloc(32);
    if (buf == NULL) {
        return 1;
    }
    if (strlen(argv[1]) >= 32) {
        fprintf(stderr, "error: name is too long\n");
        free(buf);                      /* error path frees ...           */
    } else {
        strcpy(buf, argv[1]);
        printf("Stored: %s\n", buf);
    }
    free(buf);                          /* BUG: ... and this frees again  */
    return 0;
}
