/*
 * e19_signed_unsigned_length  (SECURE)
 * CYE551 Mini Project - example 19 of 20
 *
 * Fix:   n is parsed strictly with validate_integer() and must lie in
 *        [0, sizeof buf - 1] (BOTH ends checked); it is then converted to
 *        size_t - which is safe because it is known to be non-negative -
 *        and also checked against the real length of the text.
 * Usage: ./secure <text> <n>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[32];
    long value = 0;
    size_t n;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <text> <n>\n", argv[0]);
        return 1;
    }
    if (validate_integer(argv[2], 0, (long)sizeof buf - 1, &value) != VAL_OK) {
        fprintf(stderr, "REJECTED: n must be a whole number from 0 to %zu\n",
                sizeof buf - 1);
        return 2;
    }
    n = (size_t)value;                      /* FIX: known to be >= 0 */
    if (n > strlen(argv[1])) {              /* FIX: no over-read */
        fprintf(stderr, "REJECTED: n is larger than the text\n");
        return 2;
    }
    memcpy(buf, argv[1], n);
    buf[n] = '\0';
    printf("prefix=\"%s\"\n", buf);
    return 0;
}
