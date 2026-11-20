/*
 * input_handler.c - Bounded input from stdin / files / argv
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 */
#include "input_handler.h"
#include "safe_string.h"

#include <limits.h>
#include <string.h>

/* fgets takes an int size, so a buffer must also fit in an int. */
static int buf_size_ok(size_t n)
{
    return n > 0 && n <= (size_t)INT_MAX;
}

/* Throw away the rest of the current line (up to and including '\n'). */
static void drain_line(FILE *fp)
{
    int c;
    do {
        c = fgetc(fp);
    } while (c != '\n' && c != EOF);
}

in_status input_read_line(FILE *fp, char *buf, size_t buf_size, size_t *len)
{
    size_t n;
    size_t nread;

    if (len != NULL) {
        *len = 0;
    }
    if (fp == NULL || buf == NULL) {
        return IN_ERR_NULL;
    }
    if (!buf_size_ok(buf_size)) {
        return IN_ERR_SIZE;
    }
    buf[0] = '\0';

    /* Pre-fill with a non-zero byte. fgets writes only the characters it
     * read plus one '\0', so afterwards the LAST '\0' in buf is the one
     * fgets wrote and its index is the real number of bytes read. */
    memset(buf, 'X', buf_size);

    /* fgets reads at most buf_size - 1 characters and always terminates. */
    if (fgets(buf, (int)buf_size, fp) == NULL) {
        buf[0] = '\0';
        return ferror(fp) ? IN_ERR_IO : IN_EOF;
    }

    nread = buf_size - 1;
    while (nread > 0 && buf[nread] != '\0') {
        nread--;
    }
    n = strlen(buf);   /* safe: fgets guarantees a '\0' inside buf */

    if (n != nread) {
        /* strlen() stopped before the real end: the line contains a '\0'
         * byte. Everything after it would be invisible to string functions
         * (CWE-158), so the whole line is rejected. */
        if (buf[nread - 1] != '\n') {
            drain_line(fp);
        }
        buf[0] = '\0';
        return IN_ERR_NUL_BYTE;
    }

    if (n > 0 && buf[n - 1] == '\n') {
        /* Complete line: strip the newline (and a preceding '\r'). */
        buf[--n] = '\0';
        if (n > 0 && buf[n - 1] == '\r') {
            buf[--n] = '\0';
        }
    } else if (n == buf_size - 1) {
        /* Buffer filled without seeing '\n'. Either the line is longer than
         * the buffer, or it fits exactly and '\n'/EOF comes next. Peek. */
        int c = fgetc(fp);
        if (c != '\n' && c != EOF) {
            drain_line(fp);
            if (len != NULL) {
                *len = n;
            }
            return IN_TOO_LONG;
        }
    }
    /* else: last line of the input without a trailing '\n' - accepted. */

    if (len != NULL) {
        *len = n;
    }
    return IN_OK;
}

in_status input_from_arg(int argc, char *argv[], int index,
                         char *buf, size_t buf_size)
{
    ss_status st;

    if (buf == NULL || argv == NULL) {
        return IN_ERR_NULL;
    }
    if (!buf_size_ok(buf_size)) {
        return IN_ERR_SIZE;
    }
    buf[0] = '\0';
    if (index < 0 || index >= argc || argv[index] == NULL) {
        return IN_ERR_MISSING;
    }

    /* Bounded copy instead of strcpy(buf, argv[index]). */
    st = safe_copy(buf, buf_size, argv[index]);
    return (st == SS_OK) ? IN_OK : IN_TOO_LONG;
}

in_status input_read_file(const char *path, char *buf, size_t buf_size,
                          size_t *len)
{
    FILE *fp;
    size_t n;
    in_status st = IN_OK;

    if (len != NULL) {
        *len = 0;
    }
    if (path == NULL || buf == NULL) {
        return IN_ERR_NULL;
    }
    if (!buf_size_ok(buf_size)) {
        return IN_ERR_SIZE;
    }
    buf[0] = '\0';

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return IN_ERR_IO;
    }

    /* Read at most buf_size - 1 bytes, leaving room for '\0'. */
    n = fread(buf, 1, buf_size - 1, fp);
    if (ferror(fp)) {
        st = IN_ERR_IO;
        n = 0;
    } else if (n == buf_size - 1 && fgetc(fp) != EOF) {
        st = IN_TOO_LONG;   /* more data was left in the file */
    }
    buf[n] = '\0';
    fclose(fp);

    if (len != NULL) {
        *len = n;
    }
    return st;
}

const char *in_status_str(in_status st)
{
    switch (st) {
    case IN_OK:          return "IN_OK";
    case IN_TOO_LONG:    return "IN_TOO_LONG";
    case IN_EOF:         return "IN_EOF";
    case IN_ERR_NULL:    return "IN_ERR_NULL";
    case IN_ERR_SIZE:    return "IN_ERR_SIZE";
    case IN_ERR_MISSING: return "IN_ERR_MISSING";
    case IN_ERR_IO:      return "IN_ERR_IO";
    case IN_ERR_NUL_BYTE: return "IN_ERR_NUL_BYTE";
    }
    return "IN_UNKNOWN";
}
