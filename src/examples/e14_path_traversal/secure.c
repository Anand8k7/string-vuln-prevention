/*
 * e14_path_traversal  (SECURE)
 * CYE551 Mini Project - example 14 of 20
 *
 * Fix (defence in depth):
 *   1. Whitelist: the name may contain only [A-Za-z0-9._-] (no '/'),
 *      1-64 characters, and must not start with '.' (no "..", no hidden
 *      files).
 *   2. Canonicalisation: realpath() resolves the final path (including
 *      symbolic links) and it must still lie inside the public folder.
 * Usage: ./secure <file name>    exit 0 = ok, 2 = rejected, 1 = usage
 */
#define _XOPEN_SOURCE 700           /* realpath() */

#include "safe_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "tests/fixtures/examples/public"

static int reject(const char *why)
{
    fprintf(stderr, "REJECTED: %s\n", why);
    return 2;
}

int main(int argc, char *argv[])
{
    char path[256];
    char line[128];
    char *base_real = NULL;
    char *file_real = NULL;
    size_t base_len;
    FILE *fp;
    int rc = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file name>\n", argv[0]);
        return 1;
    }
    /* 1. Whitelist validation */
    if (validate_input(argv[1], 1, 64, CHARSET_ALNUM, "._-", NULL) != VAL_OK ||
        argv[1][0] == '.') {
        return reject("file name must be 1-64 characters of [A-Za-z0-9._-] "
                      "and must not start with '.'");
    }
    if (safe_format(path, sizeof path, "%s/%s", BASE_DIR, argv[1]) != SS_OK) {
        return reject("path is too long");
    }

    /* 2. Canonical path must stay inside BASE_DIR */
    base_real = realpath(BASE_DIR, NULL);
    file_real = realpath(path, NULL);
    if (base_real == NULL) {
        rc = reject("public folder not found (run from the repository root)");
        goto out;
    }
    if (file_real == NULL) {
        rc = reject("file not found");
        goto out;
    }
    base_len = strlen(base_real);
    if (strncmp(file_real, base_real, base_len) != 0 ||
        file_real[base_len] != '/') {
        rc = reject("file is outside the public folder");
        goto out;
    }

    fp = fopen(file_real, "r");
    if (fp == NULL) {
        rc = reject("file cannot be opened");
        goto out;
    }
    while (fgets(line, sizeof line, fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);

out:
    free(base_real);
    free(file_real);
    return rc;
}
