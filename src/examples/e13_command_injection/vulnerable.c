/*
 * e13_command_injection  (VULNERABLE)
 * CYE551 Mini Project - example 13 of 20
 *
 * Bug:   user text is pasted into a shell command line and run with
 *        system(). The buffer is bounded, but the SHELL interprets
 *        characters such as ; & | $( ) ` in the name, so extra commands run.
 *        (The tests only inject a harmless "echo INJECTED".)
 * CWE:   CWE-78 (OS Command Injection)
 * Usage: ./vulnerable <name>
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    char cmd[128];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }
    snprintf(cmd, sizeof cmd, "echo Hello, %s", argv[1]);
    return system(cmd) == 0 ? 0 : 1;            /* BUG: shell + user text */
}
