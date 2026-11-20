/*
 * safe_string.h - Bounded, always-terminated string operations
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Module 2 (Validation) and Module 3 (Safe String Operations)
 *
 * Rules every function in this library follows:
 *   1. The caller always passes the TOTAL size of the destination buffer
 *      (sizeof(buf) for arrays), never "size - 1".
 *   2. Nothing is ever written at or beyond dst[dst_size - 1] except the
 *      terminating '\0'.
 *   3. If dst is non-NULL and dst_size is valid, dst is ALWAYS '\0'-terminated
 *      when the function returns, even on error.
 *   4. Truncation is never silent: it is reported through the return value so
 *      the caller can decide to reject the input.
 */
#ifndef SAFE_STRING_H
#define SAFE_STRING_H

#include <stddef.h>

/* Largest buffer size accepted. A size above this almost certainly came from
 * a negative signed value that was converted to size_t (CWE-195), so it is
 * rejected instead of being trusted. Same idea as RSIZE_MAX in C11 Annex K. */
#define SS_MAX_SIZE ((size_t)-1 >> 1)

/* Result codes shared by all string operations. */
typedef enum {
    SS_OK = 0,          /* operation completed, result fits                 */
    SS_TRUNCATED,       /* result did not fit; dst holds a terminated prefix */
    SS_ERR_NULL,        /* a required pointer was NULL                       */
    SS_ERR_SIZE,        /* dst_size is 0 or larger than SS_MAX_SIZE          */
    SS_ERR_UNTERMINATED,/* safe_concat: dst had no '\0' inside dst_size      */
    SS_ERR_FORMAT       /* safe_format: the formatting itself failed         */
} ss_status;

/* Bit flags selecting which character classes validate_input() accepts. */
#define CHARSET_ALPHA  0x01u   /* A-Z a-z                  */
#define CHARSET_DIGIT  0x02u   /* 0-9                      */
#define CHARSET_SPACE  0x04u   /* ' ' (space only, no tabs) */
#define CHARSET_ALNUM  (CHARSET_ALPHA | CHARSET_DIGIT)

/* Result codes for validation. */
typedef enum {
    VAL_OK = 0,
    VAL_ERR_NULL,       /* input pointer was NULL                     */
    VAL_ERR_EMPTY,      /* input is shorter than min_len              */
    VAL_ERR_TOO_LONG,   /* input is longer than max_len               */
    VAL_ERR_BAD_CHAR,   /* input contains a character not whitelisted */
    VAL_ERR_NOT_NUMBER, /* validate_integer: not a plain decimal int  */
    VAL_ERR_RANGE       /* validate_integer: outside [min, max]       */
} val_status;

/* ------------------------------------------------------------------------- */
/* Module 3: Safe string operations                                          */
/* ------------------------------------------------------------------------- */

/* Length of s, but never reads more than max bytes. Returns max if no '\0'
 * was found in the first max bytes. NULL -> 0. (Portable strnlen.) */
size_t safe_strlen(const char *s, size_t max);

/* Replacement for strcpy/strncpy. Copies src into dst (size dst_size),
 * always terminates, reports truncation. */
ss_status safe_copy(char *dst, size_t dst_size, const char *src);

/* Replacement for strcat/strncat. Appends src to the string already in dst.
 * dst_size is the TOTAL size of dst (not the space left). */
ss_status safe_concat(char *dst, size_t dst_size, const char *src);

/* Replacement for sprintf. printf-style formatting into dst; always
 * terminates, reports truncation. The format attribute lets the compiler
 * check every call site's arguments (-Wformat). */
ss_status safe_format(char *dst, size_t dst_size, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

/* Human-readable name of a status code (for messages and test output). */
const char *ss_status_str(ss_status st);

/* ------------------------------------------------------------------------- */
/* Module 2: Validation                                                      */
/* ------------------------------------------------------------------------- */

/* Whitelist validation. Accepts s only if
 *     min_len <= strlen(s) <= max_len
 * and every character belongs to one of the classes in `charset` or appears
 * in `extra_allowed` (may be NULL). Only ASCII is accepted; control
 * characters and bytes >= 0x80 are always rejected unless listed in
 * extra_allowed.
 * If bad_pos is non-NULL and a bad character is found, its index is stored. */
val_status validate_input(const char *s, size_t min_len, size_t max_len,
                          unsigned charset, const char *extra_allowed,
                          size_t *bad_pos);

/* Strict decimal integer parser (replacement for atoi / scanf("%d")).
 * Accepts an optional leading '-' followed by one or more digits and nothing
 * else (no spaces, no '+', no trailing junk). Values that overflow `long` or
 * fall outside [min, max] give VAL_ERR_RANGE. Stores the value in *out only
 * on success. */
val_status validate_integer(const char *s, long min, long max, long *out);

const char *val_status_str(val_status st);

#endif /* SAFE_STRING_H */
