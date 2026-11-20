/*
 * safe_string.c - Implementation of the safe string library
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 *
 * See safe_string.h for the contract. In short: every function takes the
 * full destination size, never writes past it, always leaves a '\0', and
 * reports truncation instead of hiding it.
 */
#include "safe_string.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

/* A destination size is valid if it leaves room for at least the '\0' and
 * does not look like a negative number converted to size_t. */
static int size_is_valid(size_t n)
{
    return n > 0 && n <= SS_MAX_SIZE;
}

size_t safe_strlen(const char *s, size_t max)
{
    size_t n = 0;

    if (s == NULL) {
        return 0;
    }
    /* Stop at max even if no terminator is found: never read past it. */
    while (n < max && s[n] != '\0') {
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* safe_copy: bounded strcpy                                                 */
/* ------------------------------------------------------------------------- */
ss_status safe_copy(char *dst, size_t dst_size, const char *src)
{
    size_t src_len;
    size_t n;

    if (dst == NULL) {
        return SS_ERR_NULL;
    }
    if (!size_is_valid(dst_size)) {
        return SS_ERR_SIZE;           /* cannot even store '\0' safely */
    }
    if (src == NULL) {
        dst[0] = '\0';                /* leave dst as a valid empty string */
        return SS_ERR_NULL;
    }

    /* Only look at dst_size bytes of src: if it is that long we already
     * know it will not fit, no need to scan further. */
    src_len = safe_strlen(src, dst_size);
    n = (src_len < dst_size) ? src_len : dst_size - 1;

    /* memmove instead of memcpy: correct even if src and dst overlap. */
    memmove(dst, src, n);
    dst[n] = '\0';                    /* guaranteed termination */

    return (src_len < dst_size) ? SS_OK : SS_TRUNCATED;
}

/* ------------------------------------------------------------------------- */
/* safe_concat: bounded strcat                                               */
/* ------------------------------------------------------------------------- */
ss_status safe_concat(char *dst, size_t dst_size, const char *src)
{
    size_t dst_len;

    if (dst == NULL) {
        return SS_ERR_NULL;
    }
    if (!size_is_valid(dst_size)) {
        return SS_ERR_SIZE;
    }

    /* Find the current end of dst WITHOUT reading past the buffer. If there
     * is no '\0' inside dst_size, dst is already corrupt: terminate it at
     * the last byte and refuse to append. */
    dst_len = safe_strlen(dst, dst_size);
    if (dst_len == dst_size) {
        dst[dst_size - 1] = '\0';
        return SS_ERR_UNTERMINATED;
    }
    if (src == NULL) {
        return SS_ERR_NULL;           /* dst untouched and still terminated */
    }

    /* Append into the remaining space; safe_copy does the bounds work. */
    return safe_copy(dst + dst_len, dst_size - dst_len, src);
}

/* ------------------------------------------------------------------------- */
/* safe_format: bounded sprintf                                              */
/* ------------------------------------------------------------------------- */
ss_status safe_format(char *dst, size_t dst_size, const char *fmt, ...)
{
    va_list ap;
    int written;

    if (dst == NULL) {
        return SS_ERR_NULL;
    }
    if (!size_is_valid(dst_size)) {
        return SS_ERR_SIZE;
    }
    if (fmt == NULL) {
        dst[0] = '\0';
        return SS_ERR_NULL;
    }

    /* vsnprintf writes at most dst_size bytes including the '\0' and
     * returns the length the full result WOULD have had. */
    va_start(ap, fmt);
    written = vsnprintf(dst, dst_size, fmt, ap);
    va_end(ap);

    if (written < 0) {
        dst[0] = '\0';                /* encoding error: leave dst empty */
        return SS_ERR_FORMAT;
    }
    if ((size_t)written >= dst_size) {
        return SS_TRUNCATED;          /* vsnprintf already terminated it */
    }
    return SS_OK;
}

const char *ss_status_str(ss_status st)
{
    switch (st) {
    case SS_OK:               return "SS_OK";
    case SS_TRUNCATED:        return "SS_TRUNCATED";
    case SS_ERR_NULL:         return "SS_ERR_NULL";
    case SS_ERR_SIZE:         return "SS_ERR_SIZE";
    case SS_ERR_UNTERMINATED: return "SS_ERR_UNTERMINATED";
    case SS_ERR_FORMAT:       return "SS_ERR_FORMAT";
    }
    return "SS_UNKNOWN";
}

/* ------------------------------------------------------------------------- */
/* Validation                                                                */
/* ------------------------------------------------------------------------- */

/* Explicit ASCII ranges instead of <ctype.h>: the result must not depend on
 * the current locale, and isalpha() on a negative char is undefined. */
static int char_allowed(unsigned char c, unsigned charset, const char *extra)
{
    if ((charset & CHARSET_ALPHA) &&
        ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
        return 1;
    }
    if ((charset & CHARSET_DIGIT) && c >= '0' && c <= '9') {
        return 1;
    }
    if ((charset & CHARSET_SPACE) && c == ' ') {
        return 1;
    }
    if (extra != NULL && c != '\0' && strchr(extra, (int)c) != NULL) {
        return 1;
    }
    return 0;
}

val_status validate_input(const char *s, size_t min_len, size_t max_len,
                          unsigned charset, const char *extra_allowed,
                          size_t *bad_pos)
{
    size_t len;
    size_t i;

    if (s == NULL) {
        return VAL_ERR_NULL;
    }

    /* Bounded length check first: read at most max_len + 1 bytes, which is
     * enough to know whether the input is too long. (Guard the +1 so a
     * huge max_len cannot wrap around to 0.) */
    len = safe_strlen(s, (max_len < SS_MAX_SIZE) ? max_len + 1 : max_len);
    if (len > max_len) {
        return VAL_ERR_TOO_LONG;
    }
    if (len < min_len) {
        return VAL_ERR_EMPTY;
    }

    /* Whitelist: reject on the first character that is not allowed. */
    for (i = 0; i < len; i++) {
        if (!char_allowed((unsigned char)s[i], charset, extra_allowed)) {
            if (bad_pos != NULL) {
                *bad_pos = i;
            }
            return VAL_ERR_BAD_CHAR;
        }
    }
    return VAL_OK;
}

val_status validate_integer(const char *s, long min, long max, long *out)
{
    const char *p;
    char *end = NULL;
    long value;

    if (s == NULL || out == NULL) {
        return VAL_ERR_NULL;
    }
    if (s[0] == '\0') {
        return VAL_ERR_EMPTY;
    }

    /* Format check: optional '-', then one or more digits, nothing else.
     * strtol alone would accept " 42", "+42" and "42abc". */
    p = (s[0] == '-') ? s + 1 : s;
    if (*p == '\0') {
        return VAL_ERR_NOT_NUMBER;
    }
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return VAL_ERR_NOT_NUMBER;
        }
    }

    /* Overflow check: strtol sets errno = ERANGE (atoi would silently
     * return garbage). */
    errno = 0;
    value = strtol(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0') {
        return VAL_ERR_RANGE;
    }
    if (value < min || value > max) {
        return VAL_ERR_RANGE;
    }

    *out = value;
    return VAL_OK;
}

const char *val_status_str(val_status st)
{
    switch (st) {
    case VAL_OK:             return "VAL_OK";
    case VAL_ERR_NULL:       return "VAL_ERR_NULL";
    case VAL_ERR_EMPTY:      return "VAL_ERR_EMPTY";
    case VAL_ERR_TOO_LONG:   return "VAL_ERR_TOO_LONG";
    case VAL_ERR_BAD_CHAR:   return "VAL_ERR_BAD_CHAR";
    case VAL_ERR_NOT_NUMBER: return "VAL_ERR_NOT_NUMBER";
    case VAL_ERR_RANGE:      return "VAL_ERR_RANGE";
    }
    return "VAL_UNKNOWN";
}
