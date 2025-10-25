
#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


/* compat for macOS/BSD vs Linux */

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define TCP_FLAG_SYN(th)  ((th)->th_flags & TH_SYN)
  #define TCP_FLAG_ACK(th)  ((th)->th_flags & TH_ACK)
  #define TCP_FLAG_FIN(th)  ((th)->th_flags & TH_FIN)
  #define TCP_FLAG_RST(th)  ((th)->th_flags & TH_RST)
  #define TCP_FLAG_PSH(th)  ((th)->th_flags & TH_PUSH)
  #define TCP_FLAG_URG(th)  ((th)->th_flags & TH_URG)
#else
  #define TCP_FLAG_SYN(th)  ((th)->syn)
  #define TCP_FLAG_ACK(th)  ((th)->ack)
  #define TCP_FLAG_FIN(th)  ((th)->fin)
  #define TCP_FLAG_RST(th)  ((th)->rst)
  #define TCP_FLAG_PSH(th)  ((th)->psh)
  #define TCP_FLAG_URG(th)  ((th)->urg)
#endif


#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define ICMPHDR       struct icmp
  #define ICMP_TYPE(h)  ((h)->icmp_type)
  #define ICMP_CODE(h)  ((h)->icmp_code)

  #define UDP_SPORT(u)  ntohs((u)->uh_sport)
  #define UDP_DPORT(u)  ntohs((u)->uh_dport)
  #define UDP_LEN(u)    ntohs((u)->uh_ulen)

  #define TCP_SPORT(t)  ntohs((t)->th_sport)
  #define TCP_DPORT(t)  ntohs((t)->th_dport)
  #define TCP_DOFF(t)   ((t)->th_off * 4)
#else
  #define ICMPHDR       struct icmphdr
  #define ICMP_TYPE(h)  ((h)->type)
  #define ICMP_CODE(h)  ((h)->code)

  #define UDP_SPORT(u)  ntohs((u)->source)
  #define UDP_DPORT(u)  ntohs((u)->dest)
  #define UDP_LEN(u)    ntohs((u)->len)

  #define TCP_SPORT(t)  ntohs((t)->source)
  #define TCP_DPORT(t)  ntohs((t)->dest)
  #define TCP_DOFF(t)   ((t)->doff * 4)
#endif



int parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len) {
    (void)h;
    if ((int)h->caplen < 14) return -1;
    const unsigned char *d = p;
    printf("Ethernet: dst=");
    print_mac(d);
    printf(" src=");
    print_mac(d+6);
    unsigned short et = (unsigned short)(d[12] << 8 | d[13]);
    int off = 14;
    if (et == 0x8100 && (int)h->caplen >= 18) { // VLAN
        et = (unsigned short)(d[16] << 8 | d[17]);
        off = 18;
    }
    if (g_verbose >= 2) printf(" type=0x%04x\n", et);
    else printf("\n");
    *eth_type = et;
    *l2len = off;
    return 0;
}

/* Print MAC helper */
void print_mac(const unsigned char *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* IPv4 basic details and dispatch to L4 */
void handle_ipv4(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off) {
    if ((int)h->caplen < ip_off + (int)sizeof(struct ip)) return;
    const struct ip *ip = (const struct ip *)(p + ip_off);
    int ihl = ip->ip_hl * 4;
    if ((int)h->caplen < ip_off + ihl) return;

    char src[32]={0}, dst[32]={0};
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));

    if (g_verbose >= 2) {
        printf("IPv4: %s -> %s proto=%d ttl=%d len=%d id=%d\n",
               src, dst, ip->ip_p, ip->ip_ttl, ntohs(ip->ip_len), ntohs(ip->ip_id));
    } else {
        printf("IPv4: %s -> %s\n", src, dst);
    }

    int l4off = ip_off + ihl;
    if (ip->ip_p == IPPROTO_TCP) handle_tcp(h, p, l4off);
    else if (ip->ip_p == IPPROTO_UDP) handle_udp(h, p, l4off);
    else if (ip->ip_p == IPPROTO_ICMP) handle_icmp(h, p, l4off);
}

/* ARP minimal */
void handle_arp(const struct pcap_pkthdr *h, const unsigned char *p, int off) {
    (void)h;
    const unsigned char *a = p + off;
    if ((int)h->caplen < off + 28) return; /* assume Ethernet/IPv4 */
    printf("ARP (basic)\n");
    printf("  Sender MAC: "); print_mac(a+8); printf("\n");
    printf("  Sender IP : %u.%u.%u.%u\n", a[14],a[15],a[16],a[17]);
    printf("  Target MAC: "); print_mac(a+18); printf("\n");
    printf("  Target IP : %u.%u.%u.%u\n", a[24],a[25],a[26],a[27]);
}

/* ICMPv4 minimal */
void handle_icmp(const struct pcap_pkthdr *h, const unsigned char *p, int off) {
    if ((int)h->caplen < off + (int)sizeof(ICMPHDR)) return;
    const ICMPHDR *ic = (const ICMPHDR*)(p + off);
    printf("ICMP: type=%d code=%d\n", ICMP_TYPE(ic), ICMP_CODE(ic));
}

/* UDP + simple app guesses */
void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off) {
    if ((int)h->caplen < off + (int)sizeof(struct udphdr)) return;
    const struct udphdr *uh = (const struct udphdr*)(p + off);
    unsigned short sp = UDP_SPORT(uh), dp = UDP_DPORT(uh);
    unsigned short ulen = UDP_LEN(uh);
    if (g_verbose >= 2) printf("UDP: %u -> %u len=%u\n", sp, dp, ulen);

    const unsigned char *pl = p + off + sizeof(struct udphdr);
    int plen = (int)h->caplen - (int)(pl - p);
    if (dp == 53 || sp == 53) try_dns(pl, plen);
    if (dp == 67 || dp == 68 || sp == 67 || sp == 68) try_dhcp(pl, plen);
}

/* TCP + simple HTTP peek */
void handle_tcp(const struct pcap_pkthdr *h, const unsigned char *p, int off) {
    if ((int)h->caplen < off + (int)sizeof(struct tcphdr)) return;
const struct tcphdr *th = (const struct tcphdr*)(p + off);
unsigned short sp = TCP_SPORT(th), dp = TCP_DPORT(th);
int doff = TCP_DOFF(th);
    if ((int)h->caplen < off + doff) return;
    if (g_verbose >= 2) {
    printf("TCP: %u -> %u", sp, dp);
    if (TCP_FLAG_SYN(th)) printf(" SYN");
    if (TCP_FLAG_ACK(th)) printf(" ACK");
    if (TCP_FLAG_FIN(th)) printf(" FIN");
    if (TCP_FLAG_RST(th)) printf(" RST");
    if (TCP_FLAG_PSH(th)) printf(" PSH");
    if (TCP_FLAG_URG(th)) printf(" URG");
    printf("\n");
}

    const unsigned char *pl = p + off + doff;
    int plen = (int)h->caplen - (int)(pl - p);
    if (dp == 80 || sp == 80) try_http(pl, plen);
}

/* DNS very basic: only prints that it's DNS and shows a few bytes */
void try_dns(const unsigned char *p, int len) {
    if (len <= 0) return;
    printf("  DNS (basic) - %d bytes\n", len);
    if (g_verbose == 3) hexdump(p, len, 64);
}

/* DHCP very basic: only indicates presence */
void try_dhcp(const unsigned char *p, int len) {
    if (len <= 0) return;
    printf("  DHCP/BOOTP (basic) - %d bytes\n", len);
    if (g_verbose == 3) hexdump(p, len, 64);
}

/* HTTP very basic: print first line (until \\r or \\n) */
void try_http(const unsigned char *p, int len) {
    if (len <= 0) return;
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  HTTP: ");
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}

/* Summary (v=1): keep it very basic */
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p) {
    (void)p;
    printf("%ld.%06ld len=%u\n", (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->len);
}

/* Simple hex dump */
void hexdump(const unsigned char *p, int len, int max_bytes) {
    if (len > max_bytes) len = max_bytes;
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("    ");
        printf("%02x ", p[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}
