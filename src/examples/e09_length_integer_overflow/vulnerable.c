/*
 * e09_length_integer_overflow  (VULNERABLE)
 * CYE551 Mini Project - example 9 of 20
 *
 * Scenario: a record joins two strings and stores its total length in a
 *           single byte (unsigned char, max 255).
 * Bug:   the length is calculated IN that 8-bit type, so it wraps around:
 *        200 + 100 + 1 = 301 becomes 45. malloc(45) is then followed by
 *        a copy of 301 bytes -> heap buffer overflow.
 * CWE:   CWE-190 (Integer Overflow or Wraparound), CWE-122 (Heap-based
 *        Buffer Overflow), CWE-131 (Incorrect Calculation of Buffer Size)
 * Usage: ./vulnerable <first> <second>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    unsigned char total;
    char *rec;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <first> <second>\n", argv[0]);
        return 1;
    }
    /* BUG: the sum is truncated to 8 bits (wraps at 256). */
    total = (unsigned char)(strlen(argv[1]) + strlen(argv[2]) + 1);
    rec = malloc(total);
    if (rec == NULL) {
        return 1;
    }
    strcpy(rec, argv[1]);           /* overflows when total wrapped */
    strcat(rec, argv[2]);
    printf("record of %u bytes, starts with \"%.10s\"\n", total, rec);
    free(rec);
    return 0;
}
