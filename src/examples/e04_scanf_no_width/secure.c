/*
 * e04_scanf_no_width  (SECURE)
 * CYE551 Mini Project - example 4 of 20
 *
 * Fix:   the field width "%7s" (buffer size - 1) limits the write. scanf
 *        then stops after 7 characters, so the next character is checked:
 *        if the word continues, it was too long and is rejected instead of
 *        being silently split.
 * Usage: echo <word> | ./secure      exit 0 = ok, 2 = rejected
 */
#include <stdio.h>

int main(void)
{
    char word[8];
    int next;

    if (scanf("%7s", word) != 1) {              /* FIX: width = size - 1 */
        fprintf(stderr, "REJECTED: word is missing\n");
        return 2;
    }
    next = getchar();
    if (next != EOF && next != '\n' && next != ' ' && next != '\t') {
        fprintf(stderr, "REJECTED: word is too long (max 7 characters)\n");
        return 2;
    }
    printf("word=%s\n", word);
    return 0;
}
