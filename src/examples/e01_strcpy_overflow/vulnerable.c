/*
 * e01_strcpy_overflow  (VULNERABLE)
 * CYE551 Mini Project - example 1 of 20
 *
 * Bug:   strcpy() copies until '\0' and never checks the size of the
 *        destination. A name longer than 15 characters overflows name[16].
 * CWE:   CWE-120 (Buffer Copy without Checking Size of Input),
 *        CWE-121 (Stack-based Buffer Overflow)
 * Usage: ./vulnerable <name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char name[16];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    strcpy(name, argv[1]);          /* BUG: no length check at all */
    printf("Hello, %s\n", name);
    return 0;
}
