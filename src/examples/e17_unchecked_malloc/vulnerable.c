/*
 * e17_unchecked_malloc  (VULNERABLE)
 * CYE551 Mini Project - example 17 of 20
 *
 * Bug:   the requested size comes from the user (strtoul without any
 *        checks, so "abc" -> 0 and "-1" -> ULONG_MAX) and the result of
 *        malloc() is NOT checked. An impossible size makes malloc() return
 *        NULL, and the program then writes through the NULL pointer.
 * CWE:   CWE-252 (Unchecked Return Value), CWE-690 (Unchecked Return Value
 *        to NULL Pointer Dereference), CWE-789 (Memory Allocation with
 *        Excessive Size Value)
 * Usage: ./vulnerable <buffer size in bytes>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    unsigned long n;
    char *buf;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size>\n", argv[0]);
        return 1;
    }
    n = strtoul(argv[1], NULL, 10);     /* no error checking */
    if (n < 32) {
        n = 32;                         /* silently "fixes" bad input */
    }
    buf = malloc(n);                    /* BUG: may return NULL ...       */
    snprintf(buf, n, "buffer of %lu bytes", n);   /* ... written anyway */
    printf("allocated: %s\n", buf);
    free(buf);
    return 0;
}
