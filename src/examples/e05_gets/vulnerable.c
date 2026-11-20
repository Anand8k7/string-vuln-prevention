/*
 * e05_gets  (VULNERABLE)
 * CYE551 Mini Project - example 5 of 20
 *
 * Bug:   gets() reads a whole line with NO limit at all. It was removed
 *        from the C language in C11, so <stdio.h> no longer declares it;
 *        it is declared by hand below only to demonstrate the problem.
 *        The linker still prints a warning that gets() is dangerous.
 * CWE:   CWE-242 (Use of Inherently Dangerous Function), CWE-120
 * Usage: echo <line> | ./vulnerable
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>

char *gets(char *s);                /* removed in C11; demo only */

int main(void)
{
    char line[16];

    if (gets(line) == NULL) {       /* BUG: cannot be used safely */
        fprintf(stderr, "no input\n");
        return 1;
    }
    printf("line=%s\n", line);
    return 0;
}
