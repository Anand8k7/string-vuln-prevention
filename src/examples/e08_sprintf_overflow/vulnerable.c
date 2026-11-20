/*
 * e08_sprintf_overflow  (VULNERABLE)
 * CYE551 Mini Project - example 8 of 20
 *
 * Bug:   sprintf() has no size parameter. "user=" + name + " id=42" must
 *        fit in line[32] (name at most 20 characters), but nothing checks.
 * CWE:   CWE-120, CWE-787
 * Usage: ./vulnerable <name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>

int main(int argc, char *argv[])
{
    char line[32];
    int id = 42;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    sprintf(line, "user=%s id=%d", argv[1], id);    /* BUG: unbounded */
    puts(line);
    return 0;
}
