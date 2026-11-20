/*
 * e11_unterminated_strlen  (SECURE)
 * CYE551 Mini Project - example 11 of 20
 *
 * Fix:   the field is NOT assumed to be a string. safe_strlen(field, 8)
 *        never looks at more than 8 bytes, and printf("%.*s") prints at
 *        most that many characters. A full 8-character name is valid data,
 *        so it is accepted and shown correctly.
 * Usage: printf 'ABCDEFGH' | ./secure      exit 0 = ok, 2 = rejected
 */
#include "safe_string.h"

#include <stdio.h>

int main(void)
{
    char field[8];
    size_t n, len;

    n = fread(field, 1, sizeof field, stdin);
    if (n == 0) {
        fprintf(stderr, "REJECTED: name field is missing\n");
        return 2;
    }
    len = safe_strlen(field, n);                        /* FIX: bounded */
    printf("name=%.*s len=%zu\n", (int)len, field, len);  /* FIX: bounded */
    return 0;
}
