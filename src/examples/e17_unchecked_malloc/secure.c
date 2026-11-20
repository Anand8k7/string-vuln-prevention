/*
 * e17_unchecked_malloc  (SECURE)
 * CYE551 Mini Project - example 17 of 20
 *
 * Fix:   1. the size is parsed strictly with validate_integer() and limited
 *           to a sensible range (32 bytes - 1 MiB);
 *        2. the result of malloc() is ALWAYS checked before use.
 * Usage: ./secure <size>      exit 0 = ok, 2 = rejected, 3 = out of memory
 */
#include "safe_string.h"

#include <stdio.h>
#include <stdlib.h>

#define MIN_SIZE 32L
#define MAX_SIZE (1024L * 1024L)

int main(int argc, char *argv[])
{
    long value = 0;
    size_t n;
    char *buf;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size>\n", argv[0]);
        return 1;
    }
    if (validate_integer(argv[1], MIN_SIZE, MAX_SIZE, &value) != VAL_OK) {  /* FIX 1 */
        fprintf(stderr, "REJECTED: size must be a whole number from %ld to %ld\n",
                MIN_SIZE, MAX_SIZE);
        return 2;
    }
    n = (size_t)value;
    buf = malloc(n);
    if (buf == NULL) {                                          /* FIX 2 */
        fprintf(stderr, "ERROR: out of memory\n");
        return 3;
    }
    if (safe_format(buf, n, "buffer of %zu bytes", n) != SS_OK) {
        free(buf);
        return 3;
    }
    printf("allocated: %s\n", buf);
    free(buf);
    return 0;
}
