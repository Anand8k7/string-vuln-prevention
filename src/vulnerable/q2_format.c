/*
 * q2_format.c  (VULNERABLE VERSION)
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Q2: Improper input validation + unsafe formatting
 *     (scanf("%s"), scanf("%d") unchecked, sprintf, printf(user_input))
 *
 * !!! DELIBERATELY INSECURE TEACHING EXAMPLE - DO NOT REUSE THIS CODE !!!
 * It reads only local keyboard / redirected input and contains no exploit
 * payload. It is compiled without stack protector / FORTIFY_SOURCE (see
 * Makefile) so the effects can be observed.
 *
 * Program: a small feedback form. Reads three values from standard input
 *     Name, Age, Message   (one per line)
 * echoes the message back and stores a one-line record.
 *
 * Bugs:
 *   [B1] scanf("%s", name)   - no field width: unbounded write into
 *        name[16] (CWE-120, CWE-242). It also stops at the first space, so
 *        "John Smith" is split and "Smith" is read as the next field.
 *   [B2] scanf("%d", &age)   - return value ignored (CWE-252) and no range
 *        check (CWE-20). On non-numeric input `age` is used uninitialised
 *        (CWE-457) and the text stays in stdin for the next scanf.
 *   [B3] sprintf(record, ...) - no bound on record[64] (CWE-120, CWE-787).
 *   [B4] printf(msg)          - user input used as the FORMAT STRING
 *        (CWE-134): "%p" / "%lx" print stack contents (information leak),
 *        "%s%s%s..." dereferences random values and crashes.
 *   The simulated secret below stands in for any sensitive value that
 *   lives on the stack (session key, password hash, ...).
 */
#include <stdio.h>

#define NAME_SIZE   16
#define MSG_SIZE    64
#define RECORD_SIZE 64

int main(void)
{
    /* Simulated sensitive value kept in a local variable. */
    volatile unsigned long secret_token = 0x5EC12E7AB1EUL;
    char name[NAME_SIZE];
    char msg[MSG_SIZE];
    char record[RECORD_SIZE];
    int age;                      /* [B2] not initialised */

    printf("Name: ");
    scanf("%s", name);            /* [B1] unbounded %s */

    printf("Age: ");
    scanf("%d", &age);            /* [B2] result not checked, no range */

    printf("Message: ");
    scanf("%s", msg);             /* [B1] unbounded %s again */
    printf("\n");

    /* [B4] The user's message is passed as the format string. */
    printf("Your message: ");
    printf(msg);
    printf("\n");

    /* [B3] No bound on the size of the record. */
    sprintf(record, "name=%s age=%d msg=%s", name, age, msg);
    printf("Saved record: %s\n", record);

    (void)secret_token;
    return 0;
}
