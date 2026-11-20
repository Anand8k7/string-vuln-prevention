/*
 * e03_format_string  (SECURE)
 * CYE551 Mini Project - example 3 of 20
 *
 * Fix:   the format string is a fixed literal and the user's text is only
 *        an ARGUMENT, so '%' characters are printed as they are.
 *        (-Wformat=2 -Werror in the secure build makes printf(var) an error.)
 * Usage: ./secure <text>      exit 0 = ok, 1 = usage
 */
#include <stdio.h>

/* cppcheck-suppress constParameter ; C requires main(int, char *[]) */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    printf("%s\n", argv[1]);        /* FIX: fixed format string */
    return 0;
}
