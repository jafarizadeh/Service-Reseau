#include "decode.h"
#include <stdio.h>

/* SMTP (canal de contrôle) :
   on affiche uniquement la première ligne ASCII du payload (commande ou réponse),
   jusqu'à CR/LF, pour garder l'analyse simple et lisible. */
void try_smtp(const unsigned char *p, int len)
{
    if (len <= 0) return;

    /* Recherche de fin de ligne (CR ou LF) sans dépasser len. */
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  SMTP: ");

    /* Impression ASCII “safe” : non imprimable => '.' */
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}
