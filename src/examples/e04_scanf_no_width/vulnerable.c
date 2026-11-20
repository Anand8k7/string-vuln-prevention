/*
 * e04_scanf_no_width  (VULNERABLE)
 * CYE551 Mini Project - example 4 of 20
 *
 * Bug:   scanf("%s") reads a word of ANY length into word[8]. The return
 *        value is checked here, so the only bug is the missing field width.
 * CWE:   CWE-120, CWE-242 (Use of Inherently Dangerous Function)
 * Usage: echo <word> | ./vulnerable
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>

int main(void)
{
    char word[8];

    if (scanf("%s", word) != 1) {   /* BUG: no width -> unbounded write */
        fprintf(stderr, "no input\n");
        return 1;
    }
    printf("word=%s\n", word);
    return 0;
}
