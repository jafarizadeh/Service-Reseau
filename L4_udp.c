#include "decode.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "l7.h"



/* UDP handler: prints basic info and tries DNS/DHCP */
void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(struct udphdr)) return;

    const struct udphdr *uh = (const struct udphdr *)(p + off);
    unsigned short sp = UDP_SPORT(uh);
    unsigned short dp = UDP_DPORT(uh);
    unsigned short ulen = UDP_LEN(uh);

    if (g_verbose == 3) {
        printf("UDP:\n");
        printf("  src-port=%u dst-port=%u length=%u checksum=0x%04x\n",
               sp, dp, ulen, UDP_SUM(uh));
    } else if (g_verbose >= 2) {
        printf("UDP: %u -> %u len=%u\n", sp, dp, ulen);
    }

    /* payload pointer */
    const unsigned char *pl = p + off + (int)sizeof(struct udphdr);
    int plen = (int)h->caplen - (int)(pl - p);
    if (plen < 0) plen = 0;

    /* simple app guesses by port */
    if (dp == 53 || sp == 53)           try_dns(pl, plen);
    if (dp == 67 || dp == 68 || sp == 67 || sp == 68) try_dhcp(pl, plen);
}
