/*
 * e07_strncpy_no_terminator  (VULNERABLE)
 * CYE551 Mini Project - example 7 of 20
 *
 * Bug:   strncpy(dst, src, n) does NOT add '\0' when src has n or more
 *        characters. name[8] is then not a string, and printf/strlen read
 *        past its end until they happen to find a zero byte.
 * CWE:   CWE-170 (Improper Null Termination), CWE-126 (Buffer Over-read)
 * Usage: ./vulnerable <name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char name[8];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    strncpy(name, argv[1], sizeof name);    /* BUG: no '\0' if len >= 8 */
    printf("name=%s len=%zu\n", name, strlen(name));   /* over-read */
    return 0;
}
