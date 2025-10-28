
#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "bootp.h"


/* compat for macOS/BSD vs Linux */

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define TCP_FLAG_SYN(th) ((th)->th_flags & TH_SYN)
#define TCP_FLAG_ACK(th) ((th)->th_flags & TH_ACK)
#define TCP_FLAG_FIN(th) ((th)->th_flags & TH_FIN)
#define TCP_FLAG_RST(th) ((th)->th_flags & TH_RST)
#define TCP_FLAG_PSH(th) ((th)->th_flags & TH_PUSH)
#define TCP_FLAG_URG(th) ((th)->th_flags & TH_URG)
#else
#define TCP_FLAG_SYN(th) ((th)->syn)
#define TCP_FLAG_ACK(th) ((th)->ack)
#define TCP_FLAG_FIN(th) ((th)->fin)
#define TCP_FLAG_RST(th) ((th)->rst)
#define TCP_FLAG_PSH(th) ((th)->psh)
#define TCP_FLAG_URG(th) ((th)->urg)
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define ICMPHDR struct icmp
#define ICMP_TYPE(h) ((h)->icmp_type)
#define ICMP_CODE(h) ((h)->icmp_code)

#define UDP_SPORT(u) ntohs((u)->uh_sport)
#define UDP_DPORT(u) ntohs((u)->uh_dport)
#define UDP_LEN(u) ntohs((u)->uh_ulen)

#define TCP_SPORT(t) ntohs((t)->th_sport)
#define TCP_DPORT(t) ntohs((t)->th_dport)
#define TCP_DOFF(t) ((t)->th_off * 4)
#else
#define ICMPHDR struct icmphdr
#define ICMP_TYPE(h) ((h)->type)
#define ICMP_CODE(h) ((h)->code)

#define UDP_SPORT(u) ntohs((u)->source)
#define UDP_DPORT(u) ntohs((u)->dest)
#define UDP_LEN(u) ntohs((u)->len)

#define TCP_SPORT(t) ntohs((t)->source)
#define TCP_DPORT(t) ntohs((t)->dest)
#define TCP_DOFF(t) ((t)->doff * 4)
#endif

int parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len)
{
    (void)h;
    if ((int)h->caplen < 14)
        return -1;
    const unsigned char *d = p;
    printf("Ethernet: dst=");
    print_mac(d);
    printf(" src=");
    print_mac(d + 6);
    unsigned short et = (unsigned short)(d[12] << 8 | d[13]);
    int off = 14;
    if (et == 0x8100 && (int)h->caplen >= 18)
    { // VLAN
        et = (unsigned short)(d[16] << 8 | d[17]);
        off = 18;
    }
    if (g_verbose >= 2)
        printf(" type=0x%04x\n", et);
    else
        printf("\n");
    *eth_type = et;
    *l2len = off;
    return 0;
}

/* Print MAC helper */
void print_mac(const unsigned char *m)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* IPv4 and dispatch to L4 */
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

    if (g_verbose >= 2)
    {
        printf("IPv4: %s -> %s proto=%d ttl=%d len=%d id=%d\n",
               src, dst, ip->ip_p, ip->ip_ttl, ntohs(ip->ip_len), ntohs(ip->ip_id));
    }
    else
    {
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

/* ARP */
void handle_arp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + 8)
        return;

    const unsigned char *a = p + off;
    unsigned short htype = (unsigned short)((a[0] << 8) | a[1]);
    unsigned short ptype = (unsigned short)((a[2] << 8) | a[3]);
    unsigned char hlen = a[4];
    unsigned char plen = a[5];
    unsigned short oper = (unsigned short)((a[6] << 8) | a[7]);

    int need = 8 + hlen + plen + hlen + plen;
    if ((int)h->caplen < off + need)
        return;

    const unsigned char *sha = a + 8;
    const unsigned char *spa = sha + hlen;
    const unsigned char *tha = spa + plen;
    const unsigned char *tpa = tha + hlen;

    if (g_verbose >= 2)
    {
        printf("ARP: htype=%u ptype=0x%04x hlen=%u plen=%u op=%u\n",
               (unsigned)htype, (unsigned)ptype, (unsigned)hlen, (unsigned)plen, (unsigned)oper);
    }
    else
    {
        printf("ARP\n");
    }

    printf("  Sender MAC: ");
    print_mac(sha);
    printf("\n");
    if (plen == 4)
    {
        printf("  Sender IP : %u.%u.%u.%u\n", spa[0], spa[1], spa[2], spa[3]);
    }
    else
    {
        printf("  Sender Proto: (%u bytes)\n", (unsigned)plen);
    }

    printf("  Target MAC: ");
    print_mac(tha);
    printf("\n");
    if (plen == 4)
    {
        printf("  Target IP : %u.%u.%u.%u\n", tpa[0], tpa[1], tpa[2], tpa[3]);
    }
    else
    {
        printf("  Target Proto: (%u bytes)\n", (unsigned)plen);
    }
}

/* ICMPv4 */
void handle_icmp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(ICMPHDR))
        return;
    const ICMPHDR *ic = (const ICMPHDR *)(p + off);
    printf("ICMP: type=%d code=%d\n", ICMP_TYPE(ic), ICMP_CODE(ic));
}

/* UDP + app guesses */
void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(struct udphdr))
        return;
    const struct udphdr *uh = (const struct udphdr *)(p + off);
    unsigned short sp = UDP_SPORT(uh), dp = UDP_DPORT(uh);
    unsigned short ulen = UDP_LEN(uh);
    if (g_verbose >= 2)
        printf("UDP: %u -> %u len=%u\n", sp, dp, ulen);

    const unsigned char *pl = p + off + sizeof(struct udphdr);
    int plen = (int)h->caplen - (int)(pl - p);
    if (dp == 53 || sp == 53)
        try_dns(pl, plen);
    if (dp == 67 || dp == 68 || sp == 67 || sp == 68)
        try_dhcp(pl, plen);
}

/* TCP + HTTP peek */
void handle_tcp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(struct tcphdr))
        return;
    const struct tcphdr *th = (const struct tcphdr *)(p + off);
    unsigned short sp = TCP_SPORT(th), dp = TCP_DPORT(th);
    int doff = TCP_DOFF(th);
    if ((int)h->caplen < off + doff)
        return;
    if (g_verbose >= 2)
    {
        printf("TCP: %u -> %u", sp, dp);
        if (TCP_FLAG_SYN(th))
            printf(" SYN");
        if (TCP_FLAG_ACK(th))
            printf(" ACK");
        if (TCP_FLAG_FIN(th))
            printf(" FIN");
        if (TCP_FLAG_RST(th))
            printf(" RST");
        if (TCP_FLAG_PSH(th))
            printf(" PSH");
        if (TCP_FLAG_URG(th))
            printf(" URG");
        printf("\n");
    }

    const unsigned char *pl = p + off + doff;
    int plen = (int)h->caplen - (int)(pl - p);
    if (dp == 80 || sp == 80)
        try_http(pl, plen);
    if (dp == 80 || sp == 80)
        try_http(pl, plen);
    if (dp == 21 || sp == 21)
        try_ftp(pl, plen);
    if (dp == 25 || sp == 25)
        try_smtp(pl, plen);
}

/* --- DNS helpers --- */
static unsigned short rd16(const unsigned char *b)
{
    return (unsigned short)((b[0] << 8) | b[1]);
}
static unsigned int rd32(const unsigned char *b)
{
    return (unsigned int)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static int dns_read_name(const unsigned char *msg, int msglen, int off,
                         char *out, int outsz, int *consumed)
{
    int o = off;
    int outpos = 0;
    int jumped = 0;
    int jumps = 0;
    if (consumed)
        *consumed = 0;

    while (o >= 0 && o < msglen)
    {
        unsigned char len = msg[o];
        if (len == 0)
        {
            if (!jumped && consumed)
                *consumed = (o - off) + 1;
            if (outpos == 0)
            {
                out[0] = '.';
                out[1] = '\0';
            }
            else
                out[outpos] = '\0';
            return 0;
        }
        if ((len & 0xC0) == 0xC0)
        {
            if (o + 1 >= msglen)
                return -1;
            int ptr = ((len & 0x3F) << 8) | msg[o + 1];
            if (!jumped && consumed)
                *consumed = (o - off) + 2;
            o = ptr;
            jumped = 1;
            if (++jumps > 10)
                return -1;
            continue;
        }
        else
        {
            o++;
            if (o + len > msglen)
                return -1;
            if (outpos && outpos < outsz - 1)
                out[outpos++] = '.';
            for (int i = 0; i < len && outpos < outsz - 1; i++)
            {
                unsigned char c = msg[o + i];
                out[outpos++] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            o += len;
        }
    }
    return -1;
}

void try_dns(const unsigned char *p, int len)
{
    /* DNS: header, first question (QNAME/QTYPE/QCLASS), first answer (A/AAAA/CNAME) */
    if (len < 12)
    {
        printf("  DNS (truncated)\n");
        return;
    }

    int i = 0;
    unsigned short id = rd16(p + i);
    i += 2;
    unsigned short flags = rd16(p + i);
    i += 2;
    unsigned short qd = rd16(p + i);
    i += 2;
    unsigned short an = rd16(p + i);
    i += 2;
    unsigned short ns = rd16(p + i);
    i += 2;
    unsigned short ar = rd16(p + i);
    i += 2;
    (void)flags;
    (void)ns;
    (void)ar;

    printf("  DNS: id=0x%04x qd=%u an=%u\n", id, (unsigned)qd, (unsigned)an);

    /* First question (if any) */
    if (qd > 0)
    {
        char qname[256];
        int consumed = 0;
        if (dns_read_name(p, len, i, qname, sizeof(qname), &consumed) == 0)
        {
            i += consumed;
            if (i + 4 <= len)
            {
                unsigned short qtype = rd16(p + i);
                i += 2;
                unsigned short qclass = rd16(p + i);
                i += 2;
                printf("    Q: %s  type=%u class=%u\n", qname, (unsigned)qtype, (unsigned)qclass);
            }
            else
            {
                return;
            }
        }
        else
        {
            return;
        }
    }

    /* First answer (if any) */
    if (an > 0)
    {
        char name[256];
        int consumed = 0;
        if (dns_read_name(p, len, i, name, sizeof(name), &consumed) != 0)
            return;
        i += consumed;

        if (i + 10 > len)
            return;
        unsigned short type = rd16(p + i);
        i += 2;
        unsigned short aclass = rd16(p + i);
        i += 2;
        unsigned int ttl = rd32(p + i);
        i += 4;
        unsigned short rdlen = rd16(p + i);
        i += 2;
        if (i + rdlen > len)
            return;

        printf("    A: %s  type=%u class=%u ttl=%u ", name, (unsigned)type, (unsigned)aclass, ttl);

        if (type == 1 && rdlen == 4)
        {
            printf("addr=%u.%u.%u.%u\n", p[i], p[i + 1], p[i + 2], p[i + 3]);
        }
        else if (type == 28 && rdlen == 16)
        {
            char buf[64] = {0};
            inet_ntop(AF_INET6, p + i, buf, sizeof(buf));
            printf("addr=%s\n", buf);
        }
        else if (type == 5)
        { /* CNAME */
            char cname[256];
            int cused = 0;
            if (dns_read_name(p, len, i, cname, sizeof(cname), &cused) == 0)
            {
                printf("cname=%s\n", cname);
            }
            else
            {
                printf("rdata(%u bytes)\n", (unsigned)rdlen);
            }
        }
        else
        {
            printf("rdata(%u bytes)\n", (unsigned)rdlen);
        }
    }
}

/* DHCP/BOOTP decode: header + DHCP options (53/50/51/54) */
void try_dhcp(const unsigned char *p, int len)
{
    if (len < (int)sizeof(struct bootp))
    {
        printf("  DHCP/BOOTP (truncated)\n");
        return;
    }

    const struct bootp *bp = (const struct bootp *)p;

    /* header prints */
    printf("  DHCP/BOOTP: op=%u htype=%u hlen=%u xid=0x%08x\n",
           (unsigned)bp->bp_op, (unsigned)bp->bp_htype, (unsigned)bp->bp_hlen,
           (unsigned)ntohl(bp->bp_xid));

    /* show yiaddr and client MAC (only if hlen==6 for Ethernet) */
    char yi[32] = {0};
    inet_ntop(AF_INET, &bp->bp_yiaddr, yi, sizeof(yi));
    printf("    yiaddr=%s\n", yi);

    if (bp->bp_hlen == 6)
    {
        printf("    chaddr=");
        for (int i = 0; i < 6; i++)
        {
            printf("%s%02x", (i ? ":" : ""), bp->bp_chaddr[i]);
        }
        printf("\n");
    }

    /* locate DHCP magic cookie (99 130 83 99) right after fixed header (236..239) */
    int opt_off = 236; /* BOOTP fixed header size */
    if (len < opt_off + 4)
    {
        printf("    (no DHCP magic cookie)\n");
        return;
    }
    if (p[opt_off] != 0x63 || p[opt_off + 1] != 0x82 || p[opt_off + 2] != 0x53 || p[opt_off + 3] != 0x63)
    {
        printf("    (no DHCP magic cookie)\n");
        return;
    }
    int o = opt_off + 4;

    int seen_msg = 0, seen_reqip = 0, seen_lease = 0, seen_svr = 0;

    while (o < len)
    {
        uint8_t tag = p[o++];
        if (tag == DHCP_OPT_END)
            break;
        if (tag == DHCP_OPT_PAD)
            continue;
        if (o >= len)
            break;

        uint8_t olen = p[o++];
        if (o + olen > len)
            break;

        if (tag == DHCP_OPT_MSG_TYPE && olen == 1)
        {
            uint8_t mt = p[o];
            const char *name = "UNKNOWN";
            if (mt == 1)
                name = "DISCOVER";
            else if (mt == 2)
                name = "OFFER";
            else if (mt == 3)
                name = "REQUEST";
            else if (mt == 4)
                name = "DECLINE";
            else if (mt == 5)
                name = "ACK";
            else if (mt == 6)
                name = "NAK";
            else if (mt == 7)
                name = "RELEASE";
            else if (mt == 8)
                name = "INFORM";
            printf("    opt53 msg-type=%u (%s)\n", (unsigned)mt, name);
            seen_msg = 1;
        }
        else if (tag == DHCP_OPT_REQ_IP && olen == 4)
        {
            char buf[32] = {0};
            inet_ntop(AF_INET, p + o, buf, sizeof(buf));
            printf("    opt50 requested-ip=%s\n", buf);
            seen_reqip = 1;
        }
        else if (tag == DHCP_OPT_LEASE && olen == 4)
        {
            unsigned int secs = (unsigned int)((p[o] << 24) | (p[o + 1] << 16) | (p[o + 2] << 8) | p[o + 3]);
            printf("    opt51 lease=%us\n", secs);
            seen_lease = 1;
        }
        else if (tag == DHCP_OPT_SERVER_ID && olen == 4)
        {
            char buf[32] = {0};
            inet_ntop(AF_INET, p + o, buf, sizeof(buf));
            printf("    opt54 server-id=%s\n", buf);
            seen_svr = 1;
        }

        /* move to next option */
        o += olen;

        /* stop early if we already printed the essentials */
        if (seen_msg && seen_reqip && seen_lease && seen_svr)
            break;
    }
}

/* HTTP : first line (until \\r or \\n) */
void try_http(const unsigned char *p, int len)
{
    if (len <= 0)
        return;
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n')
        n++;
    printf("  HTTP: ");
    for (int i = 0; i < n; i++)
    {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126)
            putchar(c);
        else
            putchar('.');
    }
    putchar('\n');
}

/* Summary (v=1): keep it   */
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p)
{
    (void)p;
    printf("%ld.%06ld len=%u\n", (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->len);
}

/*   hex dump */
void hexdump(const unsigned char *p, int len, int max_bytes)
{
    if (len > max_bytes)
        len = max_bytes;
    for (int i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            printf("    ");
        printf("%02x ", p[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}

/* IPv6: read fixed header and dispatch to TCP/UDP/ICMPv6 */
void handle_ipv6(const struct pcap_pkthdr *h, const unsigned char *p, int ip6_off)
{
    if ((int)h->caplen < ip6_off + (int)sizeof(struct ip6_hdr))
        return;

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(p + ip6_off);
    char src6[64] = {0}, dst6[64] = {0};
    inet_ntop(AF_INET6, &ip6->ip6_src, src6, sizeof(src6));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst6, sizeof(dst6));

    if (g_verbose >= 2)
    {
        printf("IPv6: %s -> %s nh=%d hlim=%d plen=%d\n",
               src6, dst6,
               (int)ip6->ip6_nxt,
               (int)ip6->ip6_hlim,
               (int)ntohs(ip6->ip6_plen));
    }
    else
    {
        printf("IPv6: %s -> %s\n", src6, dst6);
    }

    /* IPv6 header is 40 bytes */
    int l4off = ip6_off + 40;
    int nh = ip6->ip6_nxt;

    /* ignore extension headers for now */
    if (nh == IPPROTO_TCP)
    {
        handle_tcp(h, p, l4off);
    }
    else if (nh == IPPROTO_UDP)
    {
        handle_udp(h, p, l4off);
    }
    else if (nh == IPPROTO_ICMPV6)
    {
        handle_icmp6(h, p, l4off);
    }
    else
    {
        if (g_verbose >= 2)
            printf("Unknown IPv6 next header: %d\n", nh);
    }
}

/* ICMPv6: type/code, echo, and brief ND info */
void handle_icmp6(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(struct icmp6_hdr))
        return;

    const struct icmp6_hdr *ic6 = (const struct icmp6_hdr *)(p + off);
    unsigned char t = ic6->icmp6_type;
    unsigned char c = ic6->icmp6_code;

    printf("ICMPv6: type=%u code=%u", (unsigned)t, (unsigned)c);

    /* Echo request/reply (128/129) */
    if (t == 128 || t == 129)
    {
        printf(" (echo)");
    }

    /* Neighbor Solicitation (135) */
    if (t == ND_NEIGHBOR_SOLICIT)
    {
        if ((int)h->caplen >= off + (int)sizeof(struct nd_neighbor_solicit))
        {
            const struct nd_neighbor_solicit *ns = (const struct nd_neighbor_solicit *)(p + off);
            char tgt[64] = {0};
            inet_ntop(AF_INET6, &ns->nd_ns_target, tgt, sizeof(tgt));
            printf(" (ns target=%s)", tgt);
        }
    }
    /* Neighbor Advertisement (136) */
    else if (t == ND_NEIGHBOR_ADVERT)
    {
        if ((int)h->caplen >= off + (int)sizeof(struct nd_neighbor_advert))
        {
            const struct nd_neighbor_advert *na = (const struct nd_neighbor_advert *)(p + off);
            char tgt[64] = {0};
            inet_ntop(AF_INET6, &na->nd_na_target, tgt, sizeof(tgt));
            printf(" (na target=%s)", tgt);
        }
    }

    printf("\n");

    if (g_verbose == 3)
    {
        const unsigned char *pl = p + off + (int)sizeof(struct icmp6_hdr);
        int plen = (int)h->caplen - (int)(pl - p);
        if (plen > 0)
            hexdump(pl, plen, 64);
    }
}

/* FTP control channel */
void try_ftp(const unsigned char *p, int len) {
    if (len <= 0) return;
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  FTP: ");
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}

/* SMTP control channel */
void try_smtp(const unsigned char *p, int len) {
    if (len <= 0) return;
    int n = 0;
    while (n < len && p[n] != '\r' && p[n] != '\n') n++;
    printf("  SMTP: ");
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c >= 32 && c <= 126) putchar(c);
        else putchar('.');
    }
    putchar('\n');
}
