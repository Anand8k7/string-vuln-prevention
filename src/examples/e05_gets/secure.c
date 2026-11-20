/*
 * e05_gets  (SECURE)
 * CYE551 Mini Project - example 5 of 20
 *
 * Fix:   input_read_line() is a wrapper around fgets(): it takes the buffer
 *        size, strips the newline, drains the rest of an over-long line and
 *        reports IN_TOO_LONG, which is rejected.
 * Usage: echo <line> | ./secure      exit 0 = ok, 2 = rejected
 */
#include "input_handler.h"

#include <stdio.h>

int main(void)
{
    char line[16];
    in_status st;

    st = input_read_line(stdin, line, sizeof line, NULL);   /* FIX */
    if (st == IN_TOO_LONG) {
        fprintf(stderr, "REJECTED: line is too long (max %zu characters)\n",
                sizeof line - 1);
        return 2;
    }
    if (st != IN_OK) {
        fprintf(stderr, "REJECTED: line is missing (%s)\n", in_status_str(st));
        return 2;
    }
    printf("line=%s\n", line);
    return 0;
}
