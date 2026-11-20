/*
 * e02_strcat_overflow  (VULNERABLE)
 * CYE551 Mini Project - example 2 of 20
 *
 * Bug:   strcat() appends without knowing how much space is left.
 *        "Hello, " (7) + name + "!" (1) must fit in msg[24], so the name
 *        may have at most 15 characters - but nothing checks that.
 * CWE:   CWE-120, CWE-121
 * Usage: ./vulnerable <name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char msg[24] = "Hello, ";

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    strcat(msg, argv[1]);           /* BUG: may run past msg[23] */
    strcat(msg, "!");               /* BUG: same */
    puts(msg);
    return 0;
}
