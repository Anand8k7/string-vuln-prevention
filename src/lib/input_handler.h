/*
 * input_handler.h - Bounded input from stdin / files / argv
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Module 1 (Input Handling)
 *
 * Replaces gets(), scanf("%s") and unchecked strcpy(buf, argv[i]).
 * Every function takes the full buffer size, never writes past it and always
 * leaves buf '\0'-terminated. Input that does not fit is REPORTED (IN_TOO_LONG)
 * so the caller can reject it rather than silently use a truncated value.
 */
#ifndef INPUT_HANDLER_H
#define INPUT_HANDLER_H

#include <stddef.h>
#include <stdio.h>

typedef enum {
    IN_OK = 0,      /* a complete line / argument / file was read          */
    IN_TOO_LONG,    /* input did not fit; buf holds a terminated prefix,   */
                    /* and (for streams) the rest of the line was drained  */
    IN_EOF,         /* end of input before any character was read          */
    IN_ERR_NULL,    /* NULL pointer argument                               */
    IN_ERR_SIZE,    /* buffer size 0 or unreasonably large                 */
    IN_ERR_MISSING, /* argv index not present                              */
    IN_ERR_IO,      /* read error or file could not be opened              */
    IN_ERR_NUL_BYTE /* line contained an embedded '\0' byte (rejected)     */
} in_status;

/* Read one line from fp into buf (size buf_size) using fgets.
 * The trailing '\n' (and '\r' from Windows line endings) is removed.
 * If the line is longer than buf_size - 1, the remainder of that line is read
 * and thrown away so it cannot be picked up by the next read, and
 * IN_TOO_LONG is returned. A line containing an embedded '\0' byte is
 * discarded and IN_ERR_NUL_BYTE is returned. If len is non-NULL it receives
 * strlen(buf). */
in_status input_read_line(FILE *fp, char *buf, size_t buf_size, size_t *len);

/* Copy argv[index] into buf with bounds checking. */
in_status input_from_arg(int argc, char *argv[], int index,
                         char *buf, size_t buf_size);

/* Read the whole file at `path` into buf (at most buf_size - 1 bytes) and
 * terminate it. Returns IN_TOO_LONG if the file has more data than fits.
 * If len is non-NULL it receives the number of bytes stored. */
in_status input_read_file(const char *path, char *buf, size_t buf_size,
                          size_t *len);

const char *in_status_str(in_status st);

#endif /* INPUT_HANDLER_H */
