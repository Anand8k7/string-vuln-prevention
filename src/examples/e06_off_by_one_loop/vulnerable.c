/*
 * e06_off_by_one_loop  (VULNERABLE)
 * CYE551 Mini Project - example 6 of 20
 *
 * Bug:   two classic off-by-one mistakes together:
 *          - the check uses ">" instead of ">=", so an 8-character input
 *            is accepted for an 8-byte buffer (no room for '\0');
 *          - the loop uses "<=" so it also copies the terminator.
 *        Result: 9 bytes are written into out[8].
 * CWE:   CWE-193 (Off-by-one Error), CWE-787 (Out-of-bounds Write)
 * Usage: ./vulnerable <word>     prints the word in upper case
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char out[8];
    size_t len, i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <word>\n", argv[0]);
        return 1;
    }
    len = strlen(argv[1]);
    if (len > sizeof out) {                 /* BUG: should be >= */
        fprintf(stderr, "REJECTED: word is too long\n");
        return 2;
    }
    for (i = 0; i <= len; i++) {            /* BUG: <= writes len + 1 bytes */
        out[i] = (char)toupper((unsigned char)argv[1][i]);
    }
    printf("%s\n", out);
    return 0;
}
