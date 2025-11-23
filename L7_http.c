#include "decode.h"
#include <stdio.h>

/* HTTP :
   on affiche uniquement la première ligne du payload (requête ou réponse),
   jusqu'à CR/LF. Cela suffit pour identifier la transaction sans réassembler
   le flux TCP. */
void try_http(const unsigned char *p, int len)
{
    if (len <= 0) return;

    /* Recherche de fin de ligne (CR ou LF) sans dépasser len. */
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  HTTP: ");

    /* Impression ASCII “safe” : caractères non imprimables remplacés par '.'. */
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}
