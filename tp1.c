#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getopt
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>       // ntohs/ntohl, inet_ntop
#include <net/ethernet.h>    // struct ether_header, ETHERTYPE_*
#include <netinet/ip.h>      // struct ip (BSD/Glibc)
#include <netinet/tcp.h>     // struct tcphdr
#include <netinet/udp.h>     // struct udphdr
#include <netinet/ip_icmp.h> // struct icmphdr (or icmp on some BSDs)

/* --- ICMP portability (Linux: struct icmphdr, macOS/BSD: struct icmp) --- */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define ICMPHDR struct icmp
#define ICMP_TYPE(h) ((h)->icmp_type)
#define ICMP_CODE(h) ((h)->icmp_code)
#define ICMP_CKSUM(h) ((h)->icmp_cksum)
#else
#define ICMPHDR struct icmphdr
#define ICMP_TYPE(h) ((h)->type)
#define ICMP_CODE(h) ((h)->code)
#define ICMP_CKSUM(h) ((h)->checksum)
#endif

static int g_verbose = 2; // default v=2

// --- tiny compatibility helpers (Linux vs BSD field names) ---
// TCP header length in bytes (handle th_off vs doff)
static inline uint8_t tcp_hdr_len(const struct tcphdr *th)
{
#ifdef __APPLE__
    return (th->th_off & 0x0F) * 4;
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return (th->th_off & 0x0F) * 4;
#else
    return th->doff * 4; // glibc/linux
#endif
}

// UDP src/dst ports (uh_sport/uh_dport vs source/dest)
static inline uint16_t udp_sport(const struct udphdr *uh)
{
#ifdef __APPLE__
    return ntohs(uh->uh_sport);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return ntohs(uh->uh_sport);
#else
    return ntohs(uh->source);
#endif
}
static inline uint16_t udp_dport(const struct udphdr *uh)
{
#ifdef __APPLE__
    return ntohs(uh->uh_dport);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return ntohs(uh->uh_dport);
#else
    return ntohs(uh->dest);
#endif
}

// TCP src/dst (th_sport/th_dport vs source/dest)
static inline uint16_t tcp_sport(const struct tcphdr *th)
{
#ifdef __APPLE__
    return ntohs(th->th_sport);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return ntohs(th->th_sport);
#else
    return ntohs(th->source);
#endif
}
static inline uint16_t tcp_dport(const struct tcphdr *th)
{
#ifdef __APPLE__
    return ntohs(th->th_dport);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    return ntohs(th->th_dport);
#else
    return ntohs(th->dest);
#endif
}

/* --- TCP portability (win/check/urg) --- */
#ifdef __APPLE__
#define TCP_WIN(th) ntohs((th)->th_win)
#define TCP_SUM(th) ntohs((th)->th_sum)
#define TCP_URG(th) ntohs((th)->th_urp)
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define TCP_WIN(th) ntohs((th)->th_win)
#define TCP_SUM(th) ntohs((th)->th_sum)
#define TCP_URG(th) ntohs((th)->th_urp)
#else
#define TCP_WIN(th) ntohs((th)->window)
#define TCP_SUM(th) ntohs((th)->check)
#define TCP_URG(th) ntohs((th)->urg_ptr)
#endif

/* --- v3: compact ASCII dump of L7 payload (first max bytes) --- */
static void v3_dump_ascii(const char *label, const u_char *data, size_t len, size_t max_bytes)
{
    if (g_verbose < 3 || !data || !len)
        return;
    size_t n = len < max_bytes ? len : max_bytes;
    printf("%s (%zu bytes, showing %zu):\n", label, len, n);
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = data[i];
        putchar((c >= 32 && c <= 126) ? c : '.');
    }
    putchar('\n');
}

/* --- v3: try to show HTTP first line and Host header if present --- */
static void v3_try_http(const u_char *p, size_t len)
{
    if (g_verbose < 3 || !p || len < 4)
        return;
    /* quick heuristic: starts with method or "HTTP/" */
    const char *methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/"};
    int ok = 0;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && memcmp(p, methods[i], mlen) == 0)
        {
            ok = 1;
            break;
        }
    }
    if (!ok)
        return;

    /* print first line */
    size_t i = 0;
    printf("HTTP: ");
    while (i < len && !(p[i] == '\r' || p[i] == '\n'))
    {
        putchar((p[i] >= 32 && p[i] <= 126) ? p[i] : '.');
        i++;
    }
    putchar('\n');

    /* find Host: header (best-effort) */
    const u_char *q = NULL;
    if (len > 6)
    {
        for (size_t j = 0; j + 6 < len; j++)
        {
            if (p[j] == '\r' && p[j + 1] == '\n' && (j + 7) < len &&
                (p[j + 2] == 'H' || p[j + 2] == 'h') && (p[j + 3] == 'o' || p[j + 3] == 'O') &&
                (p[j + 4] == 's' || p[j + 4] == 'S') && (p[j + 5] == 't' || p[j + 5] == 'T') && p[j + 6] == ':')
            {
                q = p + j + 2;
                break;
            }
        }
    }
    if (q)
    {
        printf("HTTP: ");
        size_t k = 0;
        while (q + k < p + len && !(q[k] == '\r' || q[k] == '\n'))
        {
            putchar((q[k] >= 32 && q[k] <= 126) ? q[k] : '.');
            k++;
        }
        putchar('\n');
    }
}

/* --- v3: print extended IPv4 header fields (TTL/TOS/ID/flags/frag/checksum) --- */
static void v3_print_ipv4_details(const struct ip *ip)
{
    if (g_verbose < 3)
        return;
    uint16_t totlen = ntohs(ip->ip_len);
    uint16_t id = ntohs(ip->ip_id);
    uint16_t off = ntohs(ip->ip_off);
    unsigned flags = (off & 0xE000) >> 13; /* 3 bits: RF/DF/MF (RF rarely used) */
    unsigned frag = (off & 0x1FFF);        /* fragment offset in 8-byte units */
    printf("IPv4 v=4 ihl=%u tos=0x%02x totlen=%u id=0x%04x ttl=%u proto=0x%02x csum=0x%04x\n",
           ip->ip_hl * 4, ip->ip_tos, totlen, id, ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
    printf("IPv4 flags: %s %s  frag_off=%u (8B units)\n",
           (flags & 0x2) ? "DF" : "df=0",
           (flags & 0x1) ? "MF" : "mf=0",
           frag);
}

// === small safety helper: ensure we won't read beyond captured buffer ===
static int ensure_len(const struct pcap_pkthdr *hdr, size_t need)
{
    return hdr->caplen >= need; // use caplen (actual captured bytes)
}

// Compute L2 header length and EtherType (supports 1 VLAN tag)
static int parse_l2(const struct pcap_pkthdr *header, const u_char *packet,
                    size_t *l2_len, uint16_t *eth_type)
{
    if (!ensure_len(header, sizeof(struct ether_header)))
    {
        fprintf(stderr, "Truncated Ethernet: need %zu, caplen=%u\n",
                sizeof(struct ether_header), header->caplen);
        return -1;
    }
    const struct ether_header *eth = (const struct ether_header *)packet;
    uint16_t t = ntohs(eth->ether_type);
    size_t l2 = sizeof(struct ether_header);

    // VLAN tag (0x8100/0x88a8): EtherType is 4 bytes after base header
    if (t == 0x8100 || t == 0x88a8)
    {
        if (!ensure_len(header, l2 + 4))
        {
            fprintf(stderr, "Truncated VLAN header: need %zu, caplen=%u\n", l2 + 4, header->caplen);
            return -1;
        }
        t = ntohs(*(const uint16_t *)(packet + l2 + 2));
        l2 += 4;
    }

    *l2_len = l2;
    *eth_type = t;
    return 0;
}

// === Utility: Print MAC Address ===
static void print_mac(const char *label, const u_char *addr)
{
    if (g_verbose >= 2)
    {
        printf("%s%02x %02x %02x %02x %02x %02x\n",
               label, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }
}

// === Utility: Print IPv4 Address ===
static void print_ipv4(const char *label, const struct in_addr *a)
{
    if (g_verbose >= 2)
    {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, a, buf, sizeof buf);
        printf("%s%s\n", label, buf);
    }
}

// === Display ARP Packet (minimal, keep offsets) ===
static void parse_arp(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;
    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_ARP)
        return;
    if (!ensure_len(header, l2 + 28))
    {
        puts("(ARP) truncated");
        return;
    }

    printf("\n=== ARP Packet ===\n");
    print_mac("Sender MAC      : ", packet + l2 + 8);
    {
        struct in_addr sip = {.s_addr = *(const uint32_t *)(packet + l2 + 14)};
        print_ipv4("Sender IP       : ", &sip);
    }
    print_mac("Target MAC      : ", packet + l2 + 18);
    {
        struct in_addr tip = {.s_addr = *(const uint32_t *)(packet + l2 + 24)};
        print_ipv4("Target IP       : ", &tip);
    }
}

// === Display ICMP Header (IPv4) ===
static void parse_icmp(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;

    // L2 + EtherType (handles single VLAN); require IPv4
    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_IP)
        return;

    // IPv4 header and dynamic IHL
    if (!ensure_len(header, l2 + sizeof(struct ip)))
    {
        puts("(ICMP) truncated (IP)");
        return;
    }
    const struct ip *ip = (const struct ip *)(packet + l2);
    uint8_t ihl = ip->ip_hl * 4;
    if (ihl < sizeof(struct ip))
    {
        puts("(ICMP) invalid IHL");
        return;
    }
    if (!ensure_len(header, l2 + ihl + sizeof(ICMPHDR)))
    {
        puts("(ICMP) truncated (L4)");
        return;
    }

    // ICMP header (portable name via ICMPHDR macro)
    const ICMPHDR *icmph = (const ICMPHDR *)((const u_char *)ip + ihl);

    printf("\n=== ICMP Header ===\n");
    printf("Type            : %u\n", ICMP_TYPE(icmph));
    printf("Code            : %u\n", ICMP_CODE(icmph));
    printf("Checksum        : 0x%04x\n", ntohs(ICMP_CKSUM(icmph)));
}

// === Display TCP Header (IPv4) ===
static void parse_tcp(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;
    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_IP)
        return;

    if (!ensure_len(header, l2 + sizeof(struct ip)))
    {
        puts("(TCP) truncated (IP)");
        return;
    }
    const struct ip *ip = (const struct ip *)(packet + l2);
    uint8_t ihl = ip->ip_hl * 4;
    if (ihl < sizeof(struct ip))
    {
        puts("(TCP) invalid IHL");
        return;
    }
    if (!ensure_len(header, l2 + ihl + sizeof(struct tcphdr)))
    {
        puts("(TCP) truncated (L4 min)");
        return;
    }

    const struct tcphdr *th = (const struct tcphdr *)((const u_char *)ip + ihl);
    uint8_t thlen = tcp_hdr_len(th);
    if (thlen < sizeof(struct tcphdr))
    {
        puts("(TCP) invalid data offset");
        return;
    }
    if (!ensure_len(header, l2 + ihl + thlen))
    {
        puts("(TCP) truncated (options)");
        return;
    }

    printf("\n=== TCP Header ===\n");
    printf("Source Port     : %u\n", tcp_sport(th));
    printf("Destination Port: %u\n", tcp_dport(th));
#ifdef __APPLE__
    printf("Sequence Number : %u\n", ntohl(th->th_seq));
    printf("Ack Number      : %u\n", ntohl(th->th_ack));
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    printf("Sequence Number : %u\n", ntohl(th->th_seq));
    printf("Ack Number      : %u\n", ntohl(th->th_ack));
#else
    printf("Sequence Number : %u\n", ntohl(th->seq));
    printf("Ack Number      : %u\n", ntohl(th->ack_seq));
#endif

    // Flags print (portable)
    printf("Flags           : ");
#ifdef __APPLE__
    unsigned f = th->th_flags;
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    unsigned f = th->th_flags;
#else
    unsigned f = (th->fin ? 1 : 0) | (th->syn ? 2 : 0) | (th->rst ? 4 : 0) | (th->psh ? 8 : 0) |
                 (th->ack ? 16 : 0) | (th->urg ? 32 : 0);
#endif
    if (f & 0x01)
        printf("FIN ");
    if (f & 0x02)
        printf("SYN ");
    if (f & 0x04)
        printf("RST ");
    if (f & 0x08)
        printf("PSH ");
    if (f & 0x10)
        printf("ACK ");
    if (f & 0x20)
        printf("URG ");
    printf("\n");

    // Basic service hint (check both ports)
    uint16_t sp = tcp_sport(th), dp = tcp_dport(th);
    uint16_t svc = (dp < sp ? dp : sp);
    printf("Service         : ");
    switch (svc)
    {
    case 80:
        printf("HTTP\n");
        break;
    case 443:
        printf("HTTPS\n");
        break;
    case 22:
        printf("SSH\n");
        break;
    case 25:
        printf("SMTP\n");
        break;
    case 110:
        printf("POP3\n");
        break;
    case 143:
        printf("IMAP\n");
        break;
    default:
        printf("Unknown or Uncommon\n");
        break;
    }

    /* v3: extra TCP fields and payload dump */
    if (g_verbose >= 3)
    {
        printf("Window          : %u\n", TCP_WIN(th));
        printf("Checksum        : 0x%04x\n", TCP_SUM(th));
        printf("Urgent Pointer  : %u\n", TCP_URG(th));
        printf("Header Length   : %u bytes\n", thlen);
        size_t l4_payload_off = l2 + ihl + thlen;
        if (header->caplen > l4_payload_off)
        {
            size_t pay = header->caplen - l4_payload_off;
            const u_char *pl = packet + l4_payload_off;
            v3_try_http(pl, pay); /* show HTTP line if any */
            v3_dump_ascii("TCP Payload (ASCII)", pl, pay, 256);
        }
        else
        {
            printf("TCP Payload     : 0 bytes\n");
        }
    }
}

// === Display UDP Header (IPv4) ===
static void parse_udp(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;

    // L2 + EtherType (handles single VLAN); require IPv4
    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_IP)
        return;

    // IPv4 header and dynamic IHL
    if (!ensure_len(header, l2 + sizeof(struct ip)))
    {
        puts("(UDP) truncated (IP)");
        return;
    }
    const struct ip *ip = (const struct ip *)(packet + l2);
    uint8_t ihl = ip->ip_hl * 4;
    if (ihl < sizeof(struct ip))
    {
        puts("(UDP) invalid IHL");
        return;
    }
    if (ip->ip_p != IPPROTO_UDP)
        return;
    if (!ensure_len(header, l2 + ihl + sizeof(struct udphdr)))
    {
        puts("(UDP) truncated (L4)");
        return;
    }

    // UDP header
    const struct udphdr *uh = (const struct udphdr *)((const u_char *)ip + ihl);

    uint16_t sp = udp_sport(uh);
    uint16_t dp = udp_dport(uh);
#ifdef __APPLE__
    uint16_t length = ntohs(uh->uh_ulen);
    uint16_t checksum = ntohs(uh->uh_sum);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    uint16_t length = ntohs(uh->uh_ulen);
    uint16_t checksum = ntohs(uh->uh_sum);
#else
    uint16_t length = ntohs(uh->len);
    uint16_t checksum = ntohs(uh->check);
#endif

    printf("\n=== UDP Header ===\n");
    printf("Source Port     : %u\n", sp);
    printf("Destination Port: %u\n", dp);
    printf("Length          : %u bytes\n", length);
    printf("Checksum        : 0x%04x\n", checksum);

    // Simple service hint using min(src,dst)
    uint16_t svc = (dp < sp ? dp : sp);
    printf("Service         : ");
    switch (svc)
    {
    case 53:
        printf("DNS\n");
        break;
    case 67:
    case 68:
        printf("DHCP\n");
        break;
    case 123:
        printf("NTP\n");
        break;
    case 5353:
        printf("mDNS (Multicast DNS)\n");
        break;
    default:
        printf("Unknown or Uncommon\n");
        break;
    }

    /* v3: UDP payload dump */
    if (g_verbose >= 3)
    {
        size_t l4_payload_off = l2 + ihl + sizeof(struct udphdr);
        if (header->caplen > l4_payload_off)
        {
            size_t pay = header->caplen - l4_payload_off;
            const u_char *pl = packet + l4_payload_off;
            v3_dump_ascii("UDP Payload (ASCII)", pl, pay, 256);
        }
        else
        {
            printf("UDP Payload     : 0 bytes\n");
        }
    }
}

// === Display DNS Packet (kept minimal; now uses struct ip/udphdr for offsets) ===
static void parse_dns_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;
    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_IP)
        return;

    if (!ensure_len(header, l2 + sizeof(struct ip)))
        return;
    const struct ip *ip = (const struct ip *)(packet + l2);
    uint8_t ihl = ip->ip_hl * 4;
    if (ihl < sizeof(struct ip))
        return;
    if (ip->ip_p != IPPROTO_UDP)
        return;
    if (!ensure_len(header, l2 + ihl + sizeof(struct udphdr)))
        return;

    const struct udphdr *uh = (const struct udphdr *)((const u_char *)ip + ihl);
    uint16_t sp = udp_sport(uh), dp = udp_dport(uh);
    if (!(sp == 53 || dp == 53))
        return;

    const u_char *dns = (const u_char *)uh + sizeof(struct udphdr);
    if (!ensure_len(header, (dns - packet) + 12))
    {
        puts("(DNS) truncated");
        return;
    }

    uint16_t transaction_id = ntohs(*(const uint16_t *)(dns + 0));
    uint16_t flags = ntohs(*(const uint16_t *)(dns + 2));
    uint16_t questions = ntohs(*(const uint16_t *)(dns + 4));

    printf("\n=== DNS Packet ===\n");
    printf("Transaction ID   : 0x%04x\n", transaction_id);
    printf("Flags            : 0x%04x\n", flags);
    printf("Questions        : %u\n", questions);

    // Minimal QNAME printer with guards
    printf("Query Domain     : ");
    size_t idx = 12, base = (size_t)(dns - packet);
    while (ensure_len(header, base + idx + 1) && dns[idx] != 0)
    {
        uint8_t len = dns[idx++];
        if (len == 0 || len >= 63)
            break;
        if (!ensure_len(header, base + idx + len))
            break;
        for (uint8_t i = 0; i < len; i++)
            putchar(dns[idx++]);
        if (dns[idx] != 0)
            putchar('.');
    }
    putchar('\n');
}

// === Display DHCP Packet (still minimal; will be migrated to bootp.h later) ===
static void parse_dhcp_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose < 2)
        return;

    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
        return;
    if (et != ETHERTYPE_IP)
        return;

    if (!ensure_len(header, l2 + sizeof(struct ip)))
        return;
    const struct ip *ip = (const struct ip *)(packet + l2);
    uint8_t ihl = ip->ip_hl * 4;
    if (ihl < sizeof(struct ip))
        return;
    if (ip->ip_p != IPPROTO_UDP)
        return;
    if (!ensure_len(header, l2 + ihl + sizeof(struct udphdr)))
        return;

    const struct udphdr *uh = (const struct udphdr *)((const u_char *)ip + ihl);
    uint16_t sp = udp_sport(uh), dp = udp_dport(uh);
    if (!((sp == 67 || sp == 68) || (dp == 67 || dp == 68)))
        return;

    const u_char *dhcp = (const u_char *)uh + sizeof(struct udphdr);
    if (!ensure_len(header, (dhcp - packet) + 240))
    {
        puts("(DHCP/BOOTP) truncated");
        return;
    }

    uint32_t xid = ntohl(*(const uint32_t *)(dhcp + 4));
    const u_char *chaddr = dhcp + 28;

    printf("\n=== DHCP Packet ===\n");
    printf("Transaction ID   : 0x%08x\n", xid);
    printf("Client MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n",
           chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    printf("Your IP          : %u.%u.%u.%u\n", dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
}

// === Raw hex (unchanged) ===
static void print_raw_hex(const u_char *packet, size_t len)
{
    if (g_verbose >= 3)
    {
        printf("\n=== Raw Hex Dump ===\n");
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n--------------------------------------------------\n\n");
    }
}

// === Very brief summary for v=1 (now using std headers) ===
static void print_summary(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (g_verbose != 1)
        return;

    size_t l2;
    uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0)
    {
        printf("[TRUNC] caplen=%u\n", header->caplen);
        return;
    }

    if (et == ETHERTYPE_ARP)
    {
        if (!ensure_len(header, l2 + 28))
        {
            printf("[ARP] caplen=%u (trunc)\n", header->caplen);
            return;
        }
        printf("[ARP] len=%u  %u.%u.%u.%u -> %u.%u.%u.%u\n",
               header->len,
               packet[l2 + 14], packet[l2 + 15], packet[l2 + 16], packet[l2 + 17],
               packet[l2 + 24], packet[l2 + 25], packet[l2 + 26], packet[l2 + 27]);
        return;
    }

    if (et == ETHERTYPE_IP)
    {
        if (!ensure_len(header, l2 + sizeof(struct ip)))
        {
            printf("[IPv4] caplen=%u (trunc)\n", header->caplen);
            return;
        }
        const struct ip *ip = (const struct ip *)(packet + l2);
        uint8_t ihl = ip->ip_hl * 4;
        if (ihl < sizeof(struct ip))
        {
            printf("[IPv4] invalid IHL\n");
            return;
        }
        if (!ensure_len(header, l2 + ihl))
        {
            printf("[IPv4] caplen=%u (trunc ihl)\n", header->caplen);
            return;
        }

        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, src, sizeof src);
        inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof dst);

        if (ip->ip_p == IPPROTO_TCP)
        {
            if (!ensure_len(header, l2 + ihl + sizeof(struct tcphdr)))
            {
                printf("[IPv4/TCP] caplen=%u (trunc)\n", header->caplen);
                return;
            }
            const struct tcphdr *th = (const struct tcphdr *)((const u_char *)ip + ihl);
            printf("[IPv4/TCP] len=%u  %s:%u -> %s:%u\n",
                   header->len, src, tcp_sport(th), dst, tcp_dport(th));
        }
        else if (ip->ip_p == IPPROTO_UDP)
        {
            if (!ensure_len(header, l2 + ihl + sizeof(struct udphdr)))
            {
                printf("[IPv4/UDP] caplen=%u (trunc)\n", header->caplen);
                return;
            }
            const struct udphdr *uh = (const struct udphdr *)((const u_char *)ip + ihl);
            printf("[IPv4/UDP] len=%u  %s:%u -> %s:%u\n",
                   header->len, src, udp_sport(uh), dst, udp_dport(uh));
        }
        else if (ip->ip_p == IPPROTO_ICMP)
        {
            printf("[IPv4/ICMP] len=%u  %s -> %s\n", header->len, src, dst);
        }
        else
        {
            printf("[IPv4/0x%02x] len=%u  %s -> %s\n", ip->ip_p, header->len, src, dst);
        }
        return;
    }

    // (IPv6 still pending for next step)
    printf("[EtherType 0x%04x] len=%u\n", et, header->len);
}

// === Callback: Main Packet Parser ===
static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // v=1: one-line summary only
    if (g_verbose == 1) {
        print_summary(header, packet);
        return;
    }

    // L2 parsing (EtherType + VLAN) with bounds checks
    size_t l2; uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0) return;

    // Basic banner
    printf("Packet captured!\n");
    printf(" -> Length: %u bytes (caplen=%u)\n\n", header->len, header->caplen);

    // Ethernet header (standard struct)
    const struct ether_header *eth = (const struct ether_header *)packet;
    printf("=== Ethernet Header ===\n");
    print_mac("Destination MAC : ", eth->ether_dhost);
    print_mac("Source MAC      : ", eth->ether_shost);
    if (g_verbose >= 2) printf("EtherType       : 0x%04x\n", et);

    // Dispatch by EtherType
    if (et == ETHERTYPE_ARP) {
        parse_arp(header, packet);
    } else if (et == ETHERTYPE_IP) {
        // IPv4 header + dynamic IHL
        if (!ensure_len(header, l2 + sizeof(struct ip))) { puts("(IPv4) truncated"); return; }
        const struct ip *ip = (const struct ip *)(packet + l2);
        uint8_t ihl = ip->ip_hl * 4;
        if (ihl < sizeof(struct ip)) { puts("(IPv4) invalid IHL"); return; }
        if (!ensure_len(header, l2 + ihl)) { puts("(IPv4) truncated (ihl)"); return; }

        // IPv4 section
        printf("\n=== IP Header (IPv4) ===\n");
        print_ipv4("Source IP       : ", &ip->ip_src);
        print_ipv4("Destination IP  : ", &ip->ip_dst);
        printf("Protocol        : 0x%02x ", ip->ip_p);
        if (g_verbose >= 3) v3_print_ipv4_details(ip);  // extra fields in v=3

        // L4 dispatch
        switch (ip->ip_p) {
            case IPPROTO_ICMP:
                printf("(ICMP)\n");
                parse_icmp(header, packet);
                break;

            case IPPROTO_TCP:
                printf("(TCP)\n");
                parse_tcp(header, packet);
                break;

            case IPPROTO_UDP: {
                printf("(UDP)\n");
                parse_udp(header, packet);

                // Optionally parse higher-level (DNS/DHCP) if ports match
                if (!ensure_len(header, l2 + ihl + sizeof(struct udphdr))) break;
                const struct udphdr *uh = (const struct udphdr *)((const u_char *)ip + ihl);
                uint16_t sp = udp_sport(uh), dp = udp_dport(uh);
                if (sp == 53 || dp == 53) {
                    parse_dns_packet(header, packet);
                } else if ((sp == 67 || dp == 67) || (sp == 68 || dp == 68)) {
                    parse_dhcp_packet(header, packet);
                }
                break;
            }

            default:
                printf("(Unknown)\n");
                break;
        }
    } else {
        // Other L2 types not handled in this phase (e.g., IPv6)
        printf("Unknown/Unhandled EtherType, parsing skipped.\n");
    }

    // Hex dump only when v>=3
    print_raw_hex(packet, header->caplen);
}

// === Usage ===
static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s (-i <interface> | -o <pcapfile>) [-f \"bpf filter\"] [-v 1|2|3]\n"
            "  -i <iface>   Live capture interface\n"
            "  -o <file>    Read packets from pcap file (offline)\n"
            "  -f <expr>    BPF filter expression (e.g., \"tcp port 80 or arp\")\n"
            "  -v <level>   Verbosity: 1=summary, 2=synthetic (default), 3=full+hex\n",
            prog);
}

// === Apply BPF filter if provided ===
static int apply_filter(pcap_t *handle, const char *iface_or_null, const char *bpf)
{
    if (!bpf)
        return 0;
    struct bpf_program fp;
    bpf_u_int32 net = 0, mask = 0;

    if (iface_or_null)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(iface_or_null, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "pcap_lookupnet failed on %s: %s (using 0.0.0.0/0)\n", iface_or_null, errbuf);
            net = 0;
            mask = 0;
        }
    }

    if (pcap_compile(handle, &fp, bpf, 1 /*optimize*/, mask) == -1)
    {
        fprintf(stderr, "pcap_compile failed for filter '%s': %s\n", bpf, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

// === Main Function ===
int main(int argc, char *argv[])
{
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = NULL;
    char *pcapfile = NULL;
    char *bpf = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            iface = optarg;
            break;
        case 'o':
            pcapfile = optarg;
            break;
        case 'f':
            bpf = optarg;
            break;
        case 'v':
            g_verbose = atoi(optarg);
            if (g_verbose < 1 || g_verbose > 3)
            {
                fprintf(stderr, "Invalid -v value: %s (must be 1..3)\n", optarg);
                usage(argv[0]);
                return 1;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if ((iface && pcapfile) || (!iface && !pcapfile))
    {
        fprintf(stderr, "Error: specify exactly one of -i <iface> or -o <pcapfile>.\n");
        usage(argv[0]);
        return 1;
    }

    if (iface)
    {
        handle = pcap_open_live(iface, 65535, 1 /*promisc*/, 1000 /*timeout ms*/, errbuf);
        if (!handle)
        {
            fprintf(stderr, "Error opening device %s: %s\n", iface, errbuf);
            return 1;
        }
        if (pcap_datalink(handle) != DLT_EN10MB)
        {
            fprintf(stderr, "Unsupported link-layer (expecting Ethernet).\n");
            pcap_close(handle);
            return 1;
        }
        if (apply_filter(handle, iface, bpf) == -1)
        {
            pcap_close(handle);
            return 1;
        }

        printf("Live capture on %s (verbosity=%d)%s\n",
               iface, g_verbose, bpf ? " with filter" : "");
        if (bpf)
            printf("BPF: %s\n", bpf);

        int rc = pcap_loop(handle, -1, got_packet, NULL);
        if (rc == -1)
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
    }
    else
    {
        handle = pcap_open_offline(pcapfile, errbuf);
        if (!handle)
        {
            fprintf(stderr, "Error opening pcap file %s: %s\n", pcapfile, errbuf);
            return 1;
        }
        if (pcap_datalink(handle) != DLT_EN10MB)
        {
            fprintf(stderr, "Unsupported link-layer (expecting Ethernet).\n");
            pcap_close(handle);
            return 1;
        }
        if (apply_filter(handle, NULL, bpf) == -1)
        {
            pcap_close(handle);
            return 1;
        }

        printf("Offline read from %s (verbosity=%d)%s\n",
               pcapfile, g_verbose, bpf ? " with filter" : "");
        if (bpf)
            printf("BPF: %s\n", bpf);

        int rc = pcap_loop(handle, -1, got_packet, NULL);
        if (rc == -1)
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
    }
    return 0;
}
