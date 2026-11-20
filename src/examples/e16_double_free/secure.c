/*
 * e16_double_free  (SECURE)
 * CYE551 Mini Project - example 16 of 20
 *
 * Fix:   a single clean-up point: every path jumps to "out", which frees
 *        the buffer exactly once. The pointer is set to NULL after free()
 *        (free(NULL) is a harmless no-op, so a second free could not hurt).
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 32

int main(int argc, char *argv[])
{
    char *buf;
    int rc = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    buf = malloc(BUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 3;
    }
    if (safe_copy(buf, BUF_SIZE, argv[1]) != SS_OK) {
        fprintf(stderr, "REJECTED: name is too long (max %d characters)\n",
                BUF_SIZE - 1);
        rc = 2;
        goto out;                       /* FIX: no free() here */
    }
    printf("Stored: %s\n", buf);

out:
    free(buf);                          /* FIX: the only free() */
    buf = NULL;
    return rc;
}
