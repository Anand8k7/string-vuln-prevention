/*
 * q1_overflow.c  (VULNERABLE VERSION)
 *
 * CYE551 Mini Project: Implementing Prevention Methods for String Vulnerabilities
 * Q1: Buffer overflow through strcpy / strcat
 *
 * !!! DELIBERATELY INSECURE TEACHING EXAMPLE - DO NOT REUSE THIS CODE !!!
 * It reads only local command-line input and contains no exploit payload.
 * It is compiled without stack protector / FORTIFY_SOURCE (see Makefile) so
 * that the memory corruption can be observed.
 *
 * Program: builds a simple user account record from two arguments
 *     ./q1_overflow <username> <department>
 * and prints a greeting and the user's home directory path.
 *
 * Bugs (all from functions that do not know the destination size):
 *   [B1] strcpy(acct.username, argv[1])       - CWE-120 / CWE-787
 *        username[16]: a 16-char name writes its '\0' into role[0]
 *        (off-by-one, CWE-193); longer names overwrite acct.role.
 *   [B2] strcat(greeting, acct.username)      - CWE-120
 *        greeting[32] can overflow when the name is long.
 *   [B3] strcpy/strcat chain into path[32]    - CWE-121 (stack overflow)
 *        "/home/" + dept + "/" + username has no length check at all.
 *   [B4] No validation of the input at all    - CWE-20
 */
#include <stdio.h>
#include <string.h>

#define NAME_SIZE 16
#define ROLE_SIZE 16
#define MSG_SIZE  32
#define PATH_SIZE 32

/* username is directly followed by role in memory, so writing past the end
 * of username silently changes role. */
struct account {
    char username[NAME_SIZE];
    char role[ROLE_SIZE];
};

int main(int argc, char *argv[])
{
    struct account acct;
    char greeting[MSG_SIZE];
    char path[PATH_SIZE];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <department>\n", argv[0]);
        return 1;
    }

    /* Every new account starts as an unprivileged guest. */
    strcpy(acct.role, "guest");

    /* [B1] No length check: argv[1] can be any length. */
    strcpy(acct.username, argv[1]);

    /* [B2] Build "Welcome, <username>!" - no check that it fits in 32 bytes. */
    strcpy(greeting, "Welcome, ");
    strcat(greeting, acct.username);
    strcat(greeting, "!");

    /* [B3] Build "/home/<dept>/<username>" - no check that it fits either. */
    strcpy(path, "/home/");
    strcat(path, argv[2]);
    strcat(path, "/");
    strcat(path, acct.username);

    printf("%s\n", greeting);
    printf("Username : %s\n", acct.username);
    printf("Role     : %s\n", acct.role);
    printf("Home dir : %s\n", path);
    return 0;
}
