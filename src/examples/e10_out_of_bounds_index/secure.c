/*
 * e10_out_of_bounds_index  (SECURE)
 * CYE551 Mini Project - example 10 of 20
 *
 * Fix:   validate_integer() accepts only plain decimal numbers in [1, 12]
 *        (no "abc", "12x", overflow, ...). The index is then provably in
 *        range, and it is computed with an unsigned type.
 * Usage: ./secure <month 1-12>   exit 0 = ok, 2 = rejected, 1 = usage
 */
#include "safe_string.h"

#include <stdio.h>

static const char *const months[12] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

int main(int argc, char *argv[])
{
    long m = 0;
    size_t idx;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <month 1-12>\n", argv[0]);
        return 1;
    }
    if (validate_integer(argv[1], 1, 12, &m) != VAL_OK) {   /* FIX */
        fprintf(stderr, "REJECTED: month must be a whole number from 1 to 12\n");
        return 2;
    }
    idx = (size_t)(m - 1);                      /* 0..11, checked above */
    printf("Month %ld is %s\n", m, months[idx]);
    return 0;
}
