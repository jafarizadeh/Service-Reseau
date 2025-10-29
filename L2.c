#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include "decode.h"

static unsigned short rd16(const unsigned char *q) {
    unsigned short x; memcpy(&x, q, 2); return (unsigned short)ntohs(x);
}


int parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len)
{
    if ((int)h->caplen < 14) return -1;

    const unsigned char *dmac = p + 0;
    const unsigned char *smac = p + 6;
    unsigned short et = rd16(p + 12);

    if (g_verbose >= 2) {
        printf("Ethernet: dst="); print_mac(dmac);
        printf(" src=");          print_mac(smac);
        printf(" type=0x%04x\n", et);
    }

    if (eth_type) *eth_type = (int)et;
    if (l2len)    *l2len    = 14;
    return 0;
}
