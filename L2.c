#include <stdio.h>
#include <net/ethernet.h>
#include "decode.h"

/* MAC printer is in util.c */

int parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len) {
    if ((int)h->caplen < 14) return -1;

    const unsigned char *d = p;
    printf("Ethernet: dst="); print_mac(d);
    printf(" src=");          print_mac(d + 6);

    unsigned short et = (unsigned short)(d[12] << 8 | d[13]);
    int off = 14;

    /* VLAN 802.1Q */
    if (et == 0x8100 && (int)h->caplen >= 18) {
        unsigned short tci = (unsigned short)((d[14] << 8) | d[15]);
        unsigned int pcp = (tci >> 13) & 0x7;
        unsigned int dei = (tci >> 12) & 0x1;
        unsigned int vid = tci & 0x0FFF;
        if (g_verbose == 3)
            printf("  802.1Q: PCP=%u DEI=%u VID=%u\n", pcp, dei, vid);
        et = (unsigned short)(d[16] << 8 | d[17]);
        off = 18;
    }

    if (g_verbose >= 2) printf(" type=0x%04x\n", et); else printf("\n");
    *eth_type = et;
    *l2len    = off;
    return 0;
}