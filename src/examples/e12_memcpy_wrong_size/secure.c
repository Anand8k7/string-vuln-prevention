/*
 * e12_memcpy_wrong_size  (SECURE)
 * CYE551 Mini Project - example 12 of 20
 *
 * Fix:   the number of bytes to copy is computed from the DATA
 *        (strlen + 1 for the '\0') and checked against the DESTINATION
 *        size before memcpy is called.
 * Usage: ./secure <text>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char src[64];
    char dst[16];
    size_t n;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    if (safe_copy(src, sizeof src, argv[1]) != SS_OK) {
        fprintf(stderr, "REJECTED: text is too long (max %zu characters)\n",
                sizeof dst - 1);
        return 2;
    }
    n = strlen(src) + 1;                        /* FIX: size of the data */
    if (n > sizeof dst) {                       /* FIX: fits destination? */
        fprintf(stderr, "REJECTED: text is too long (max %zu characters)\n",
                sizeof dst - 1);
        return 2;
    }
    memcpy(dst, src, n);
    printf("copied: %s\n", dst);
    return 0;
}
