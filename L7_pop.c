#include <stdio.h>
#include <ctype.h>
#include "decode.h"

static int find_ci(const char *s, int n, const char *pat) {
    int m = 0;
    while (pat[m]) m++;
    if (m == 0 || n < m) return -1;

    for (int i = 0; i <= n - m; i++) {
        int ok = 1;
        for (int j = 0; j < m; j++) {
            char a = s[i + j], b = pat[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) { ok = 0; break; }
        }
        if (ok) return i;
    }
    return -1;
}

/* POP3 first-line peek; masks password in "PASS ..." */
void try_pop3(const unsigned char *p, int len) {
    if (len <= 0) return;

    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;

    char line[256];
    int m = (n < (int)sizeof(line) - 1) ? n : (int)sizeof(line) - 1;
    for (int i = 0; i < m; i++) {
        unsigned char c = p[i];
        line[i] = (c >= 32 && c <= 126) ? (char)c : '.';
    }
    line[m] = '\0';

    int pos = find_ci(line, m, "PASS ");
    if (pos >= 0) {
        for (int j = pos + 5; j < m; j++) {
            if (line[j] != ' ') line[j] = '*';
        }
    }

    printf("  POP3: %s\n", line);
}
