/*
 * e09_length_integer_overflow  (SECURE)
 * CYE551 Mini Project - example 9 of 20
 *
 * Fix:   the length is calculated in size_t, with an explicit check that
 *        the addition cannot wrap, and it is compared with the format's
 *        limit (UCHAR_MAX) BEFORE it is narrowed to one byte. The heap
 *        buffer is then filled with safe_copy/safe_concat.
 * Usage: ./secure <first> <second>   exit 0 = ok, 2 = rejected, 3 = no memory
 */
#include "safe_string.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    size_t la, lb, total;
    unsigned char stored;
    char *rec;
    int rc = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <first> <second>\n", argv[0]);
        return 1;
    }
    la = strlen(argv[1]);
    lb = strlen(argv[2]);
    if (la > SIZE_MAX - 1 || lb > SIZE_MAX - 1 - la) {     /* FIX: no wrap */
        fprintf(stderr, "REJECTED: input is too long\n");
        return 2;
    }
    total = la + lb + 1;
    if (total > UCHAR_MAX) {                               /* FIX: limit */
        fprintf(stderr, "REJECTED: record is too long (max %d bytes)\n",
                UCHAR_MAX);
        return 2;
    }
    stored = (unsigned char)total;          /* safe: total <= 255 */

    rec = malloc(total);
    if (rec == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 3;
    }
    if (safe_copy(rec, total, argv[1]) != SS_OK ||
        safe_concat(rec, total, argv[2]) != SS_OK) {
        fprintf(stderr, "INTERNAL ERROR: length mismatch\n");
        rc = 3;
    } else {
        printf("record of %u bytes, starts with \"%.10s\"\n", stored, rec);
    }
    free(rec);
    return rc;
}
