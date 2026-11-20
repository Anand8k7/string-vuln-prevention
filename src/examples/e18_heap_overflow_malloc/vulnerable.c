/*
 * e18_heap_overflow_malloc  (VULNERABLE)
 * CYE551 Mini Project - example 18 of 20
 *
 * Bug:   a home-made strdup(): malloc(strlen(s)) forgets the byte for the
 *        '\0', so strcpy() writes ONE byte past the heap block on every
 *        call. The program usually looks fine (malloc rounds sizes up),
 *        which is exactly why this bug survives in real code.
 * CWE:   CWE-122 (Heap-based Buffer Overflow), CWE-131 (Incorrect
 *        Calculation of Buffer Size), CWE-193 (Off-by-one Error)
 * Usage: ./vulnerable <text>     prints the text in upper case
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *copy;
    size_t i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <text>\n", argv[0]);
        return 1;
    }
    copy = malloc(strlen(argv[1]));     /* BUG: no room for '\0' */
    if (copy == NULL) {
        return 1;
    }
    strcpy(copy, argv[1]);              /* writes strlen + 1 bytes */
    for (i = 0; copy[i] != '\0'; i++) {
        copy[i] = (char)toupper((unsigned char)copy[i]);
    }
    printf("%s\n", copy);
    free(copy);
    return 0;
}
