#include "decode.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

/* UDP field compatibility (BSD/macOS vs Linux) */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define UDP_SPORT(u) ntohs((u)->uh_sport)
  #define UDP_DPORT(u) ntohs((u)->uh_dport)
  #define UDP_LEN(u)   ntohs((u)->uh_ulen)
  #define UDP_SUM(u)   ntohs((u)->uh_sum)
#else
  #define UDP_SPORT(u) ntohs((u)->source)
  #define UDP_DPORT(u) ntohs((u)->dest)
  #define UDP_LEN(u)   ntohs((u)->len)
  #define UDP_SUM(u)   ntohs((u)->check)
#endif

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
