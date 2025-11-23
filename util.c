
#include <stdio.h>
#include "decode.h"

/* Affiche une ligne très concise (mode -v 1) : horodatage + longueur de trame */
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p) {
    (void)p; /* pas utilisé ici */
    printf("%ld.%06ld len=%u\n",
           (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->len);
}

/* Affiche une adresse MAC au format canonique xx:xx:xx:xx:xx:xx. */
void print_mac(const unsigned char *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}


void hexdump(const unsigned char *p, int len, int max_bytes) {
    if (len > max_bytes) len = max_bytes;
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("    ");  
        printf("%02x ", p[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}
