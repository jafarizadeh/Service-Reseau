#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>


void handle_ipv4(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off)
{
    if ((int)h->caplen < ip_off + (int)sizeof(struct ip))
        return;

    const struct ip *ip = (const struct ip *)(p + ip_off);
    int ihl = ip->ip_hl * 4;
    if ((int)h->caplen < ip_off + ihl)
        return;

    char src[32] = {0}, dst[32] = {0};
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

    if (g_verbose == 3) {
        unsigned int ver  = ip->ip_v;
        unsigned int tos  = ip->ip_tos;
        unsigned int dscp = (tos >> 2) & 0x3F;
        unsigned int ecn  = tos & 0x3;
        unsigned short tlen = ntohs(ip->ip_len);
        unsigned short id   = ntohs(ip->ip_id);
        unsigned short offf = ntohs(ip->ip_off);
        unsigned int df  = (offf & 0x4000) ? 1U : 0U;
        unsigned int mf  = (offf & 0x2000) ? 1U : 0U;
        unsigned int frag_off = offf & 0x1FFF;
        unsigned short sum = ntohs(ip->ip_sum);
        unsigned int opts = (ihl > 20) ? (unsigned)(ihl - 20) : 0U;

        printf("IPv4: %s -> %s\n", src, dst);
        printf("  version=%u ihl=%u dscp=%u ecn=%u\n", ver, (unsigned)ihl, dscp, ecn);
        printf("  total-length=%u id=%u flags:DF=%u MF=%u frag-offset=%u\n",
               tlen, id, df, mf, frag_off);
        printf("  ttl=%u proto=%u hdr-checksum=0x%04x\n",
               ip->ip_ttl, ip->ip_p, sum);
        if (opts) printf("  options-bytes=%u\n", opts);
    } else if (g_verbose >= 2) {
        printf("IPv4: %s -> %s proto=%d ttl=%d len=%d id=%d\n",
               src, dst, ip->ip_p, ip->ip_ttl,
               (int)ntohs(ip->ip_len), (int)ntohs(ip->ip_id));
    } else {
        printf("IPv4: %s -> %s\n", src, dst);
    }

    
    int l4off = ip_off + ihl;
    if (ip->ip_p == IPPROTO_TCP)
        handle_tcp(h, p, l4off);
    else if (ip->ip_p == IPPROTO_UDP)
        handle_udp(h, p, l4off);
    else if (ip->ip_p == IPPROTO_ICMP)
        handle_icmp(h, p, l4off);
}
