#include "decode.h"
#include <stdio.h>

/* FTP (canal de contrôle) :
   on affiche uniquement la première ligne ASCII du payload,
   jusqu'à CR/LF, pour rester pédagogique et simple. */
void try_ftp(const unsigned char *p, int len)
{
    if (len <= 0) return;

    /* Recherche de fin de ligne (CR ou LF) sans dépasser len. */
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  FTP: ");

    /* Impression ASCII “safe” : caractères non imprimables remplacés par '.'. */
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}
