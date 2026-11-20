/*
 * e10_out_of_bounds_index  (VULNERABLE)
 * CYE551 Mini Project - example 10 of 20
 *
 * Bug:   the month number from the user is used as an array index without
 *        a range check (and atoi() cannot report bad input). 0, 13, -5 or
 *        1000 read outside months[12] and dereference whatever is there.
 * CWE:   CWE-129 (Improper Validation of Array Index),
 *        CWE-125 (Out-of-bounds Read)
 * Usage: ./vulnerable <month 1-12>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>

static const char *months[12] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

int main(int argc, char *argv[])
{
    int m;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <month 1-12>\n", argv[0]);
        return 1;
    }
    m = atoi(argv[1]);
    printf("Month %d is %s\n", m, months[m - 1]);   /* BUG: no bounds check */
    return 0;
}
