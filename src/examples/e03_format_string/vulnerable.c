/*
 * e03_format_string  (VULNERABLE)
 * CYE551 Mini Project - example 3 of 20
 *
 * Bug:   the user's text is used as the FORMAT string. Every '%' in it is
 *        interpreted: "%p" prints stack/register values (information
 *        leak), "%s%s%s" dereferences random values (crash).
 * CWE:   CWE-134 (Use of Externally-Controlled Format String)
 * Usage: ./vulnerable <text>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    printf(argv[1]);                /* BUG: user text as format */
    printf("\n");
    return 0;
}
