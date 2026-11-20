/*
 * e20_strtok_reentrancy  (VULNERABLE)
 * CYE551 Mini Project - example 20 of 20
 *
 * Scenario: parse "key=value,key=value,..." and print every pair.
 * Bug:   strtok() keeps ONE hidden, global position. The inner strtok()
 *        calls (splitting on '=') overwrite the position of the outer loop
 *        (splitting on ','), so parsing silently stops after the first
 *        pair. strtok() is also not thread-safe for the same reason, and
 *        it modifies its input.
 * CWE:   CWE-663 (Use of a Non-reentrant Function in a Concurrent Context),
 *        CWE-20 (data silently lost / not validated)
 * Usage: ./vulnerable "a=1,b=2,c=3"
 *
 * !!! Deliberately insecure teaching example - do not reuse. !!!
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char buf[128];
    char *pair, *key, *value;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key=value,...>\n", argv[0]);
        return 1;
    }
    snprintf(buf, sizeof buf, "%s", argv[1]);
    for (pair = strtok(buf, ","); pair != NULL; pair = strtok(NULL, ",")) {
        key = strtok(pair, "=");            /* BUG: resets strtok's state */
        value = strtok(NULL, "=");
        printf("%s = %s\n", key ? key : "(none)", value ? value : "(none)");
    }
    return 0;
}
