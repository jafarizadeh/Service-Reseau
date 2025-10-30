#include <stdio.h>
#include <netinet/udp.h>
#include "decode.h"

void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off) {
    if ((int)h->caplen < off + (int)sizeof(struct udphdr)) return;

    const struct udphdr *uh = (const struct udphdr *)(p + off);
    unsigned short sp = UDP_SPORT(uh), dp = UDP_DPORT(uh);
    unsigned short ulen = UDP_LEN(uh);

    if (g_verbose == 3) {
        printf("UDP:\n");
        printf("  src-port=%u dst-port=%u length=%u checksum=0x%04x\n",
               sp, dp, ulen, UDP_SUM(uh));
    } else if (g_verbose >= 2) {
        printf("UDP: %u -> %u len=%u\n", sp, dp, ulen);
    }



}
