/*
 * e14_path_traversal  (VULNERABLE)
 * CYE551 Mini Project - example 14 of 20
 *
 * Scenario: show a file from the public folder
 *           tests/fixtures/examples/public/ (run from the repository root).
 * Bug:   the file name is appended to the folder without any check, so
 *        "../secret.txt" walks out of the public folder.
 * CWE:   CWE-22 (Path Traversal)
 * Usage: ./vulnerable <file name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>

#define BASE_DIR "tests/fixtures/examples/public/"

int main(int argc, char *argv[])
{
    char path[256];
    char line[128];
    FILE *fp;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file name>\n", argv[0]);
        return 1;
    }
    snprintf(path, sizeof path, "%s%s", BASE_DIR, argv[1]);  /* BUG: "../" */
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror(path);
        return 1;
    }
    while (fgets(line, sizeof line, fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);
    return 0;
}
