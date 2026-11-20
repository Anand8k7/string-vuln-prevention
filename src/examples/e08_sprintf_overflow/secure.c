/*
 * e08_sprintf_overflow  (SECURE)
 * CYE551 Mini Project - example 8 of 20
 *
 * Fix:   snprintf() writes at most sizeof(line) bytes including '\0' and
 *        returns the length the full result WOULD have had. A negative
 *        value (encoding error) or a value >= sizeof(line) (truncated) is
 *        rejected.
 * Usage: ./secure <name>      exit 0 = ok, 2 = rejected, 1 = usage
 */
#include <stdio.h>

/* cppcheck-suppress constParameter ; C requires main(int, char *[]) */
int main(int argc, char *argv[])
{
    char line[32];
    int id = 42;
    int n;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    n = snprintf(line, sizeof line, "user=%s id=%d", argv[1], id);  /* FIX */
    if (n < 0 || (size_t)n >= sizeof line) {                       /* FIX */
        fprintf(stderr, "REJECTED: name is too long (line max %zu characters)\n",
                sizeof line - 1);
        return 2;
    }
    puts(line);
    return 0;
}
