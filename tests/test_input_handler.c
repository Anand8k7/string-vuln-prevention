/*
 * test_input_handler.c - Unit tests for src/lib/input_handler.c
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Module 1 (Input Handling) / Module 5 (Testing & Evaluation)
 *
 * Stream input is simulated with tmpfile(), so the tests need no keyboard
 * and give the same result every run. Built with ASan + UBSan.
 */
#define _POSIX_C_SOURCE 200809L   /* mkstemp, close, unlink */

#include "input_handler.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AREA_SIZE (64 + TF_GUARD_LEN)

/* Create an in-memory-like stream containing `len` bytes of `data`. */
static FILE *make_stream(const char *data, size_t len)
{
    FILE *fp = tmpfile();
    if (fp == NULL) {
        perror("tmpfile");
        exit(2);
    }
    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        perror("fwrite");
        exit(2);
    }
    rewind(fp);
    return fp;
}

/* "IN_TOO_LONG" -> "TOO_LONG,len=7" */
static const char *in_txt(char *out, size_t out_size, in_status st, size_t len)
{
    snprintf(out, out_size, "%s,len=%zu", in_status_str(st) + 3, len);
    return out;
}

/* ------------------------------------------------------------------------- */
static void test_read_line(void)
{
    char area[AREA_SIZE];
    char e[TF_TEXT], a[TF_TEXT];
    char *big;
    size_t len;
    in_status st, st2;
    FILE *fp;

    /* Normal */
    fp = make_stream("hello\n", 6);
    tf_guard_init(area, sizeof area);
    st = input_read_line(fp, area, 16, &len);
    TF_CHECK("RL-01", "Normal", "\"hello\\n\" into buf[16]",
             in_txt(e, sizeof e, IN_OK, 5), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "hello") == 0 && tf_guard_ok(area, 16));
    fclose(fp);

    fp = make_stream("hi\r\n", 4);
    st = input_read_line(fp, area, 16, &len);
    TF_CHECK("RL-02", "Normal", "Windows line ending \"hi\\r\\n\"",
             in_txt(e, sizeof e, IN_OK, 2), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "hi") == 0);
    fclose(fp);

    fp = make_stream("one\ntwo\n", 8);
    st = input_read_line(fp, area, 16, &len);
    st2 = input_read_line(fp, area, 16, &len);
    snprintf(a, sizeof a, "%s,\"%.20s\"", in_status_str(st2) + 3, area);
    TF_CHECK("RL-03", "Normal", "two lines read one after another",
             "OK,\"two\"", a, st == IN_OK && st2 == IN_OK &&
             strcmp(area, "two") == 0);
    fclose(fp);

    /* Boundary */
    fp = make_stream("abcdefg\nnext\n", 13);
    tf_guard_init(area, sizeof area);
    st = input_read_line(fp, area, 8, &len);
    TF_CHECK("RL-04", "Boundary", "7 chars + '\\n' into buf[8] (fits)",
             in_txt(e, sizeof e, IN_OK, 7), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "abcdefg") == 0 && tf_guard_ok(area, 8));
    st = input_read_line(fp, area, 8, &len);
    snprintf(a, sizeof a, "%s,\"%.20s\"", in_status_str(st) + 3, area);
    TF_CHECK("RL-05", "Boundary", "...next read gets the next line",
             "OK,\"next\"", a, st == IN_OK && strcmp(area, "next") == 0);
    fclose(fp);

    fp = make_stream("abcdefg", 7);
    st = input_read_line(fp, area, 8, &len);
    TF_CHECK("RL-06", "Boundary", "7 chars at EOF, no '\\n', buf[8]",
             in_txt(e, sizeof e, IN_OK, 7), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "abcdefg") == 0);
    fclose(fp);

    fp = make_stream("abcdefgh\nnext\n", 14);
    tf_guard_init(area, sizeof area);
    st = input_read_line(fp, area, 8, &len);
    TF_CHECK("RL-07", "Boundary", "8 chars into buf[8] (one too many)",
             in_txt(e, sizeof e, IN_TOO_LONG, 7), in_txt(a, sizeof a, st, len),
             st == IN_TOO_LONG && strcmp(area, "abcdefg") == 0 &&
             tf_guard_ok(area, 8));
    st = input_read_line(fp, area, 8, &len);
    snprintf(a, sizeof a, "%s,\"%.20s\"", in_status_str(st) + 3, area);
    TF_CHECK("RL-08", "Boundary", "...leftover 'h' was drained",
             "OK,\"next\"", a, st == IN_OK && strcmp(area, "next") == 0);
    fclose(fp);

    /* Invalid */
    fp = make_stream("", 0);
    st = input_read_line(fp, area, 16, &len);
    TF_CHECK("RL-09", "Invalid", "empty input (immediate EOF)",
             in_txt(e, sizeof e, IN_EOF, 0), in_txt(a, sizeof a, st, len),
             st == IN_EOF && area[0] == '\0');
    fclose(fp);

    fp = make_stream("ab\0cd\nnext\n", 11);
    st = input_read_line(fp, area, 16, &len);
    st2 = input_read_line(fp, area, 16, &len);
    snprintf(a, sizeof a, "%s,then \"%.20s\"", in_status_str(st) + 3, area);
    TF_CHECK("RL-10", "Invalid", "embedded NUL \"ab\\0cd\\n\" rejected",
             "ERR_NUL_BYTE,then \"next\"", a,
             st == IN_ERR_NUL_BYTE && st2 == IN_OK && strcmp(area, "next") == 0);
    fclose(fp);

    fp = make_stream("ab\0cd", 5);
    st = input_read_line(fp, area, 16, &len);
    TF_CHECK("RL-11", "Invalid", "embedded NUL on last line (no '\\n')",
             in_txt(e, sizeof e, IN_ERR_NUL_BYTE, 0), in_txt(a, sizeof a, st, len),
             st == IN_ERR_NUL_BYTE && area[0] == '\0');
    fclose(fp);

    st = input_read_line(NULL, area, 16, &len);
    TF_CHECK("RL-12", "Invalid", "stream = NULL",
             in_txt(e, sizeof e, IN_ERR_NULL, 0), in_txt(a, sizeof a, st, len),
             st == IN_ERR_NULL);

    fp = make_stream("x\n", 2);
    tf_guard_init(area, sizeof area);
    st = input_read_line(fp, area, 0, &len);
    TF_CHECK("RL-13", "Invalid", "buf_size = 0 (nothing written)",
             in_txt(e, sizeof e, IN_ERR_SIZE, 0), in_txt(a, sizeof a, st, len),
             st == IN_ERR_SIZE && tf_guard_ok(area, 0));
    fclose(fp);

    /* Oversized: 5000-char line, then a normal line. */
    big = malloc(5000 + 6);
    if (big == NULL) {
        exit(2);
    }
    memset(big, 'A', 5000);
    memcpy(big + 5000, "\nok\n", 4);
    fp = make_stream(big, 5004);
    free(big);
    tf_guard_init(area, sizeof area);
    st = input_read_line(fp, area, 16, &len);
    TF_CHECK("RL-14", "Oversized", "5000-char line into buf[16]",
             in_txt(e, sizeof e, IN_TOO_LONG, 15), in_txt(a, sizeof a, st, len),
             st == IN_TOO_LONG && len == 15 && tf_guard_ok(area, 16));
    st = input_read_line(fp, area, 16, &len);
    snprintf(a, sizeof a, "%s,\"%.20s\"", in_status_str(st) + 3, area);
    TF_CHECK("RL-15", "Oversized", "...next line is read correctly",
             "OK,\"ok\"", a, st == IN_OK && strcmp(area, "ok") == 0);
    fclose(fp);
}

/* ------------------------------------------------------------------------- */
static void test_from_arg(void)
{
    char area[AREA_SIZE];
    char e[TF_TEXT], a[TF_TEXT];
    char long_arg[301];
    char *argv[5];
    int argc = 4;
    in_status st;

    memset(long_arg, 'L', sizeof long_arg - 1);
    long_arg[sizeof long_arg - 1] = '\0';
    argv[0] = "prog";
    argv[1] = "alice";
    argv[2] = "abcdefg";
    argv[3] = long_arg;
    argv[4] = NULL;

    tf_guard_init(area, sizeof area);
    st = input_from_arg(argc, argv, 1, area, 16);
    TF_CHECK("AR-01", "Normal", "argv[1] = \"alice\" into buf[16]",
             in_txt(e, sizeof e, IN_OK, 5), in_txt(a, sizeof a, st, strlen(area)),
             st == IN_OK && strcmp(area, "alice") == 0 && tf_guard_ok(area, 16));

    tf_guard_init(area, sizeof area);
    st = input_from_arg(argc, argv, 2, area, 8);
    TF_CHECK("AR-02", "Boundary", "7-char argument into buf[8]",
             in_txt(e, sizeof e, IN_OK, 7), in_txt(a, sizeof a, st, strlen(area)),
             st == IN_OK && strcmp(area, "abcdefg") == 0 && tf_guard_ok(area, 8));

    st = input_from_arg(argc, argv, 4, area, 16);
    TF_CHECK("AR-03", "Invalid", "argument index past argc",
             in_txt(e, sizeof e, IN_ERR_MISSING, 0),
             in_txt(a, sizeof a, st, strlen(area)),
             st == IN_ERR_MISSING && area[0] == '\0');

    st = input_from_arg(argc, argv, -1, area, 16);
    TF_CHECK("AR-04", "Invalid", "negative argument index",
             in_txt(e, sizeof e, IN_ERR_MISSING, 0),
             in_txt(a, sizeof a, st, strlen(area)),
             st == IN_ERR_MISSING && area[0] == '\0');

    tf_guard_init(area, sizeof area);
    st = input_from_arg(argc, argv, 3, area, 16);
    TF_CHECK("AR-05", "Oversized", "300-char argument into buf[16]",
             in_txt(e, sizeof e, IN_TOO_LONG, 15),
             in_txt(a, sizeof a, st, strlen(area)),
             st == IN_TOO_LONG && strlen(area) == 15 && tf_guard_ok(area, 16));
}

/* ------------------------------------------------------------------------- */
/* Write `len` bytes to a new temporary file; path is stored in `path`. */
static void make_file(char *path, size_t path_size, const char *data, size_t len)
{
    int fd;
    FILE *fp;

    snprintf(path, path_size, "/tmp/svp_test_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        exit(2);
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL || (len > 0 && fwrite(data, 1, len, fp) != len)) {
        perror("write temp file");
        exit(2);
    }
    fclose(fp);
}

static void test_read_file(void)
{
    char area[AREA_SIZE];
    char path[64];
    char e[TF_TEXT], a[TF_TEXT];
    size_t len;
    in_status st;

    make_file(path, sizeof path, "config=1\n", 9);
    tf_guard_init(area, sizeof area);
    st = input_read_file(path, area, 32, &len);
    TF_CHECK("RF-01", "Normal", "9-byte file into buf[32]",
             in_txt(e, sizeof e, IN_OK, 9), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "config=1\n") == 0 &&
             tf_guard_ok(area, 32));
    unlink(path);

    make_file(path, sizeof path, "abcdefg", 7);
    tf_guard_init(area, sizeof area);
    st = input_read_file(path, area, 8, &len);
    TF_CHECK("RF-02", "Boundary", "7-byte file into buf[8] (exact fit)",
             in_txt(e, sizeof e, IN_OK, 7), in_txt(a, sizeof a, st, len),
             st == IN_OK && strcmp(area, "abcdefg") == 0 && tf_guard_ok(area, 8));
    unlink(path);

    make_file(path, sizeof path, "abcdefgh", 8);
    tf_guard_init(area, sizeof area);
    st = input_read_file(path, area, 8, &len);
    TF_CHECK("RF-03", "Boundary", "8-byte file into buf[8] (one over)",
             in_txt(e, sizeof e, IN_TOO_LONG, 7), in_txt(a, sizeof a, st, len),
             st == IN_TOO_LONG && strcmp(area, "abcdefg") == 0 &&
             tf_guard_ok(area, 8));
    unlink(path);

    st = input_read_file("/nonexistent/dir/file.txt", area, 16, &len);
    TF_CHECK("RF-04", "Invalid", "file does not exist",
             in_txt(e, sizeof e, IN_ERR_IO, 0), in_txt(a, sizeof a, st, len),
             st == IN_ERR_IO && area[0] == '\0');

    {
        char big[4096];
        memset(big, 'F', sizeof big);
        make_file(path, sizeof path, big, sizeof big);
        tf_guard_init(area, sizeof area);
        st = input_read_file(path, area, 16, &len);
        TF_CHECK("RF-05", "Oversized", "4096-byte file into buf[16]",
                 in_txt(e, sizeof e, IN_TOO_LONG, 15),
                 in_txt(a, sizeof a, st, len),
                 st == IN_TOO_LONG && len == 15 && tf_guard_ok(area, 16));
        unlink(path);
    }
}

int main(void)
{
    test_read_line();
    test_from_arg();
    test_read_file();
    return tf_report("input_handler");
}
