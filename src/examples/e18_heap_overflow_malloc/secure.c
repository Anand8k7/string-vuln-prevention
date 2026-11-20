/*
 * e18_heap_overflow_malloc  (SECURE)
 * CYE551 Mini Project - example 18 of 20
 *
 * Fix:   the allocation size is strlen + 1 (room for '\0'), the input
 *        length is limited (1-4096) so the +1 cannot overflow, malloc() is
 *        checked, and the copy is done with safe_copy() using that size.
 * Usage: ./secure <text>      exit 0 = ok, 2 = rejected, 3 = out of memory
 */
#include "safe_string.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEXT 4096

int main(int argc, char *argv[])
{
    char *copy;
    size_t len, i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    len = safe_strlen(argv[1], MAX_TEXT + 1);
    if (len == 0 || len > MAX_TEXT) {
        fprintf(stderr, "REJECTED: text must be 1-%d characters\n", MAX_TEXT);
        return 2;
    }
    copy = malloc(len + 1);                     /* FIX: + 1 for '\0' */
    if (copy == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 3;
    }
    if (safe_copy(copy, len + 1, argv[1]) != SS_OK) {   /* FIX: bounded */
        free(copy);
        return 3;
    }
    for (i = 0; i < len; i++) {
        copy[i] = (char)toupper((unsigned char)copy[i]);
    }
    printf("%s\n", copy);
    free(copy);
    return 0;
}
