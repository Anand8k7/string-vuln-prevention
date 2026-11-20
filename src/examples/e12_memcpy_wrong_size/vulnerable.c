/*
 * e12_memcpy_wrong_size  (VULNERABLE)
 * CYE551 Mini Project - example 12 of 20
 *
 * Bug:   memcpy() is given the size of the SOURCE buffer (64) instead of
 *        the size of the data / the destination (16). It writes 48 bytes
 *        past dst on EVERY call, even for short, harmless input.
 * CWE:   CWE-805 (Buffer Access with Incorrect Length Value), CWE-787
 * Usage: ./vulnerable <text>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char src[64];
    char dst[16];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    snprintf(src, sizeof src, "%s", argv[1]);   /* work copy (bounded) */
    memcpy(dst, src, sizeof src);               /* BUG: wrong size */
    dst[sizeof dst - 1] = '\0';
    printf("copied: %s\n", dst);
    return 0;
}
