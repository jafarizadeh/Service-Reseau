#include "decode.h"
#include <stdio.h>

void handle_arp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    /* ARP a au minimum 8 octets (HTYPE, PTYPE, HLEN, PLEN, OPER). */
    if ((int)h->caplen < off + 8)
        return;

    /* Champs fixes ARP (big-endian). */
    const unsigned char *a = p + off;
    unsigned short htype = (unsigned short)((a[0] << 8) | a[1]);
    unsigned short ptype = (unsigned short)((a[2] << 8) | a[3]);
    unsigned char  hlen  = a[4];
    unsigned char  plen  = a[5];
    unsigned short oper  = (unsigned short)((a[6] << 8) | a[7]);

    /* On ne sait vraiment afficher que le cas Ethernet (hlen=6). */
    if (hlen < 6)
        return;

    /* Longueur totale ARP dépendante de HLEN/PLEN : 8 + SHA+SPA+THA+TPA. */
    int need = 8 + hlen + plen + hlen + plen;
    if ((int)h->caplen < off + need)
        return;

    /* Pointeurs vers les adresses ARP dans la trame. */
    const unsigned char *sha = a + 8;
    const unsigned char *spa = sha + hlen;
    const unsigned char *tha = spa + plen;
    const unsigned char *tpa = tha + hlen;

    if (g_verbose >= 2) {
        printf("ARP: htype=%u ptype=0x%04x hlen=%u plen=%u op=%u\n",
               (unsigned)htype, (unsigned)ptype, (unsigned)hlen,
               (unsigned)plen, (unsigned)oper);
    } else {
        printf("ARP\n");
    }

    printf("  Sender MAC: ");
    print_mac(sha);
    printf("\n");

    if (plen == 4) {
        printf("  Sender IP : %u.%u.%u.%u\n", spa[0], spa[1], spa[2], spa[3]);
    } else {
        printf("  Sender Proto: (%u bytes)\n", (unsigned)plen);
    }

    printf("  Target MAC: ");
    print_mac(tha);
    printf("\n");
    if (plen == 4) {
        printf("  Target IP : %u.%u.%u.%u\n", tpa[0], tpa[1], tpa[2], tpa[3]);
    } else {
        printf("  Target Proto: (%u bytes)\n", (unsigned)plen);
    }
}
