/*
 * e06_off_by_one_loop  (SECURE)
 * CYE551 Mini Project - example 6 of 20
 *
 * Fix:   the check is "len >= sizeof out" (leave one byte for '\0'), the
 *        loop runs while i < len, and the terminator is written explicitly
 *        at out[len], which is now guaranteed to be inside the buffer.
 * Usage: ./secure <word>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* cppcheck-suppress constParameter ; C requires main(int, char *[]) */
int main(int argc, char *argv[])
{
    char out[8];
    size_t len, i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <word>\n", argv[0]);
        return 1;
    }
    len = strlen(argv[1]);
    if (len >= sizeof out) {                /* FIX: room for '\0' */
        fprintf(stderr, "REJECTED: word is too long (max %zu characters)\n",
                sizeof out - 1);
        return 2;
    }
    for (i = 0; i < len; i++) {             /* FIX: strictly less than */
        out[i] = (char)toupper((unsigned char)argv[1][i]);
    }
    out[len] = '\0';                        /* FIX: explicit terminator */
    printf("%s\n", out);
    return 0;
}
