/*
 * e19_signed_unsigned_length  (VULNERABLE)
 * CYE551 Mini Project - example 19 of 20
 *
 * Scenario: copy the first <n> characters of <text> into buf[32].
 * Bug:   n is a signed int. The check only rejects n that is too LARGE, so
 *        a negative n passes; memcpy() then converts it to size_t, and -1
 *        becomes 18446744073709551615. It also never checks n <= strlen.
 * CWE:   CWE-195 (Signed to Unsigned Conversion Error), CWE-839 (Numeric
 *        Range Comparison Without Minimum Check), CWE-787
 * Usage: ./vulnerable <text> <n>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[32];
    int n;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <text> <n>\n", argv[0]);
        return 1;
    }
    n = atoi(argv[2]);
    if (n > (int)sizeof buf - 1) {          /* BUG: no check for n < 0 */
        fprintf(stderr, "REJECTED: n is too large\n");
        return 2;
    }
    memcpy(buf, argv[1], n);                /* BUG: -1 -> huge size_t */
    buf[n] = '\0';
    printf("prefix=\"%s\"\n", buf);
    return 0;
}
