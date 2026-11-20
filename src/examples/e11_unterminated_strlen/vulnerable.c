/*
 * e11_unterminated_strlen  (VULNERABLE)
 * CYE551 Mini Project - example 11 of 20
 *
 * Scenario: a record has a fixed 8-byte name field. Short names are padded
 *           with '\0', but a name of exactly 8 characters has NO '\0'.
 * Bug:   the field is treated as a C string: strlen() and printf("%s")
 *        keep reading past field[7] until they find a zero byte somewhere.
 * CWE:   CWE-170 (Improper Null Termination), CWE-126 (Buffer Over-read)
 * Usage: printf 'ABCDEFGH' | ./vulnerable     (field read from stdin)
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char field[8];
    size_t n;

    n = fread(field, 1, sizeof field, stdin);
    if (n == 0) {
        fprintf(stderr, "no input\n");
        return 1;
    }
    if (n < sizeof field) {
        field[n] = '\0';            /* short field: terminated */
    }
    /* BUG: a full 8-byte field has no terminator. */
    printf("name=%s len=%zu\n", field, strlen(field));
    return 0;
}
