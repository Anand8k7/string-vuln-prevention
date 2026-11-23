"""samples.py - one-click samples for the Code Scanner, Runtime Check and
Input Tester tabs."""

SCAN_SAMPLES = {
    "Mixed string bugs": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gets(char *s);            /* removed from C11, declared for the demo */

void greet(const char *user)
{
    char name[16];
    char msg[32];
    strcpy(name, user);                     /* no size check */
    strcat(msg, name);                      /* no space check */
    sprintf(msg, "Hello %s!", name);        /* unbounded */
    printf(msg);                            /* user data as format */
}

int main(int argc, char *argv[])
{
    char line[32], word[8], tag[8];
    int age;

    gets(line);
    scanf("%s", word);
    scanf("%d", &age);
    strncpy(tag, line, sizeof tag);

    char *copy = malloc(strlen(line));
    memcpy(copy, line, strlen(line));

    for (int i = 0; i <= sizeof word; i++)
        word[i] = 'x';

    if (argc > 1) {
        char cmd[64];
        snprintf(cmd, sizeof cmd, "ls %s", argv[1]);
        system(cmd);
        greet(argv[1]);
    }
    printf("%d\n", atoi(line));
    free(copy);
    return 0;
}
''',
    "Secure version (should score high)": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char line[32];
    char name[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return 1;
    line[strcspn(line, "\n")] = '\0';

    int n = snprintf(name, sizeof name, "%s", line);
    if (n < 0 || (size_t)n >= sizeof name) {
        fprintf(stderr, "REJECTED: name too long\n");
        return 2;
    }

    size_t len = strlen(name);
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return 1;
    memcpy(copy, name, len + 1);

    for (size_t i = 0; i < len; i++)
        putchar(copy[i]);
    printf("\nHello, %s\n", copy);
    free(copy);
    return 0;
}
''',
}

RUNTIME_SAMPLES = {
    "Stack overflow (strcpy)": {
        "code": r'''#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char name[16];
    if (argc < 2) {
        fprintf(stderr, "usage: prog <name>\n");
        return 1;
    }
    strcpy(name, argv[1]);              /* overflows name[16] */
    printf("Hello, %s\n", name);
    return 0;
}
''',
        "stdin": "",
        "args": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
    "Heap overflow (malloc(strlen))": {
        "code": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char line[64];
    if (fgets(line, sizeof line, stdin) == NULL)
        return 1;
    line[strcspn(line, "\n")] = '\0';

    char *copy = malloc(strlen(line));  /* no room for '\0' */
    if (copy == NULL)
        return 1;
    strcpy(copy, line);                 /* writes 1 byte past the block */
    printf("copy = %s\n", copy);
    free(copy);
    return 0;
}
''',
        "stdin": "hello world\n",
        "args": "",
    },
    "Use after free": {
        "code": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *user = malloc(16);
    if (user == NULL)
        return 1;
    snprintf(user, 16, "%s", "alice");
    free(user);
    printf("Goodbye, %s\n", user);      /* user was already freed */
    return 0;
}
''',
        "stdin": "",
        "args": "",
    },
    "Double free": {
        "code": r'''#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *buf = malloc(32);
    if (buf == NULL)
        return 1;
    strcpy(buf, "temp");
    free(buf);
    free(buf);                          /* freed twice */
    return 0;
}
''',
        "stdin": "",
        "args": "",
    },
    "Off-by-one loop": {
        "code": r'''#include <stdio.h>

int main(void)
{
    char word[8];
    for (int i = 0; i <= 8; i++)        /* writes word[8] */
        word[i] = 'A';
    word[7] = '\0';
    printf("%s\n", word);
    return 0;
}
''',
        "stdin": "",
        "args": "",
    },
    "Memory leak": {
        "code": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    for (int i = 0; i < 3; i++) {
        char *p = malloc(20);
        if (p == NULL)
            return 1;
        strcpy(p, "never freed");
    }
    puts("done");
    return 0;
}
''',
        "stdin": "",
        "args": "",
    },
}

INPUT_SAMPLES = {
    "Normal input": {"name": "alice", "role": "cse", "age": "21", "message": "hello"},
    "Long name (overflow)": {"name": "AAAAAAAAAAAAAAAAAAAA", "role": "cse", "age": "21",
                             "message": "hello"},
    "Format string": {"name": "bob", "role": "ise", "age": "30", "message": "%p.%p.%p.%p"},
    # %27$lx reads the stack slot holding secret_token in the plain
    # vulnerable build (same case as Q2-20 in tests/scenarios/q2_format.sh)
    "Leak the secret": {"name": "eve", "role": "cse", "age": "22", "message": "%27$lx"},
    "Bad age": {"name": "carol", "role": "ece", "age": "abc", "message": "hello"},
    "Long message (record overflow)": {"name": "dave", "role": "cse", "age": "40",
                                       "message": "B" * 60},
}
