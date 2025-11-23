#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

/* IPv6: fixed header parse + simple L4 dispatch */
void handle_ipv6(const struct pcap_pkthdr *h, const unsigned char *p, int ip6_off)
{
    if ((int)h->caplen < ip6_off + (int)sizeof(struct ip6_hdr))
        return;

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(p + ip6_off);
    char src6[64] = {0}, dst6[64] = {0};
    inet_ntop(AF_INET6, &ip6->ip6_src, src6, sizeof(src6));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst6, sizeof(dst6));

    if (g_verbose == 3) {
        uint32_t vtf = ntohl(ip6->ip6_flow);
        unsigned int ver  = (vtf >> 28) & 0xF;
        unsigned int tcls = (vtf >> 20) & 0xFF;
        unsigned int flow = vtf & 0xFFFFF;
        printf("IPv6: %s -> %s\n", src6, dst6);
        printf("  version=%u tclass=%u flow=0x%05x\n", ver, tcls, flow);
        printf("  payload-length=%u next-header=%u hop-limit=%u\n",
               (unsigned)ntohs(ip6->ip6_plen),
               (unsigned)ip6->ip6_nxt,
               (unsigned)ip6->ip6_hlim);
    } else if (g_verbose >= 2) {
        printf("IPv6: %s -> %s nh=%d hlim=%d plen=%d\n",
               src6, dst6,
               (int)ip6->ip6_nxt,
               (int)ip6->ip6_hlim,
               (int)ntohs(ip6->ip6_plen));
    } else {
        printf("IPv6: %s -> %s\n", src6, dst6);
    }

    /* IPv6 fixed header is 40 bytes; ignoring extension headers */
    int l4off = ip6_off + 40;
    int nh = ip6->ip6_nxt;

    if (nh == IPPROTO_TCP)
        handle_tcp(h, p, l4off);
    else if (nh == IPPROTO_UDP)
        handle_udp(h, p, l4off);
    else if (nh == IPPROTO_ICMPV6)
        handle_icmp6(h, p, l4off);
}
