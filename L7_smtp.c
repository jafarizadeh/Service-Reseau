#include "decode.h"
#include <stdio.h>

/* SMTP control line */
void try_smtp(const unsigned char *p, int len)
{
    if (len <= 0) return;
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  SMTP: ");
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}
