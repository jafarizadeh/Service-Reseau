#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

static int g_verbose = 2; // default v=2

// === helpers for endian-safe reads ===
static inline uint16_t rd16(const void *p) {
    uint16_t v; memcpy(&v, p, sizeof v); return ntohs(v);
}
static inline uint32_t rd32(const void *p) {
    uint32_t v; memcpy(&v, p, sizeof v); return ntohl(v);
}

// === small safety helper: ensure we won't read beyond captured buffer ===
// Use caplen (captured length), not len (original on-wire length).
static int ensure_len(const struct pcap_pkthdr *hdr, size_t need) {
    return hdr->caplen >= need;
}

// Compute L2 header length and EtherType (handles single VLAN tag).
// Returns 0 on success, -1 on truncation/unsupported.
static int parse_l2(const struct pcap_pkthdr *header, const u_char *packet,
                    size_t *l2_len, uint16_t *eth_type) {
    if (!ensure_len(header, 14)) {
        fprintf(stderr, "Truncated Ethernet: need 14, caplen=%u\n", header->caplen);
        return -1;
    }
    uint16_t t = rd16(packet + 12);
    size_t l2 = 14;

    // Single VLAN tag support (802.1Q / 802.1ad). For multiple tags, expand if needed.
    if (t == 0x8100 || t == 0x88a8) {
        if (!ensure_len(header, 18)) {
            fprintf(stderr, "Truncated VLAN header: need 18, caplen=%u\n", header->caplen);
            return -1;
        }
        t = rd16(packet + 16);
        l2 = 18;
    }

    *l2_len = l2;
    *eth_type = t;
    return 0;
}

// === Utility: Print MAC Address ===
void print_mac(const char *label, const u_char *addr) {
    if (g_verbose >= 2) {
        printf("%s", label);
        for (int i = 0; i < 6; i++) printf("%02x%s", addr[i], i==5?"\n":" ");
    }
}

// === Utility: Print IP Address (IPv4 only) ===
void print_ip(const char *label, const u_char *addr) {
    if (g_verbose >= 2) {
        printf("%s%d.%d.%d.%d\n", label, addr[0], addr[1], addr[2], addr[3]);
    }
}

// === Display ARP Packet ===
void parse_arp(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;
    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0806) return; // ARP
    if (!ensure_len(header, l2 + 28)) { puts("(ARP) truncated"); return; }
    // Offsets below assume Ethernet/IPv4 ARP with standard sizes.

    printf("\n=== ARP Packet ===\n");
    print_mac("Sender MAC      : ", packet + l2 + 8);
    print_ip ("Sender IP       : ", packet + l2 + 14);
    print_mac("Target MAC      : ", packet + l2 + 18);
    print_ip ("Target IP       : ", packet + l2 + 24);
}

// === Display ICMP Header (IPv4) ===
void parse_icmp(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;
    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0800) return; // IPv4
    if (!ensure_len(header, l2 + 20)) { puts("(ICMP) truncated (IP)"); return; }

    const u_char *ip = packet + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) { puts("(ICMP) invalid IHL"); return; }
    if (!ensure_len(header, l2 + ihl + 4)) { puts("(ICMP) truncated (L4)"); return; }

    const u_char *icmp = ip + ihl;

    printf("\n=== ICMP Header ===\n");
    printf("Type            : %u\n", icmp[0]);
    printf("Code            : %u\n", icmp[1]);
    printf("Checksum        : 0x%04x\n", rd16(icmp + 2));
}

// === Display TCP Header (IPv4) ===
void parse_tcp(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;
    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0800) return;

    if (!ensure_len(header, l2 + 20)) { puts("(TCP) truncated (IP)"); return; }
    const u_char *ip = packet + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) { puts("(TCP) invalid IHL"); return; }
    if (!ensure_len(header, l2 + ihl + 14)) { puts("(TCP) truncated (L4 min)"); return; }

    const u_char *tcp = ip + ihl;
    uint16_t src_port = rd16(tcp + 0);
    uint16_t dst_port = rd16(tcp + 2);
    uint32_t seq = rd32(tcp + 4);
    uint32_t ack = rd32(tcp + 8);
    uint8_t  doff = ((tcp[12] >> 4) & 0x0F) * 4;
    uint8_t  flags = tcp[13];

    if (!ensure_len(header, l2 + ihl + doff)) { puts("(TCP) truncated (options)"); return; }

    printf("\n=== TCP Header ===\n");
    printf("Source Port     : %u\n", src_port);
    printf("Destination Port: %u\n", dst_port);
    printf("Sequence Number : %u\n", seq);
    printf("Ack Number      : %u\n", ack);

    printf("Flags           : ");
    if (flags & 0x01) printf("FIN ");
    if (flags & 0x02) printf("SYN ");
    if (flags & 0x04) printf("RST ");
    if (flags & 0x08) printf("PSH ");
    if (flags & 0x10) printf("ACK ");
    if (flags & 0x20) printf("URG ");
    printf("\n");

    // Basic service hint: check both src/dst ports
    uint16_t svc = (dst_port < src_port ? dst_port : src_port);
    printf("Service         : ");
    switch (svc) {
        case 80:  printf("HTTP\n"); break;
        case 443: printf("HTTPS\n"); break;
        case 22:  printf("SSH\n"); break;
        case 25:  printf("SMTP\n"); break;
        case 110: printf("POP3\n"); break;
        case 143: printf("IMAP\n"); break;
        default:  printf("Unknown or Uncommon\n"); break;
    }
}

// === Display UDP Header (IPv4) ===
void parse_udp(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;
    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0800) return;

    if (!ensure_len(header, l2 + 20)) { puts("(UDP) truncated (IP)"); return; }
    const u_char *ip = packet + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) { puts("(UDP) invalid IHL"); return; }
    if (!ensure_len(header, l2 + ihl + 8)) { puts("(UDP) truncated (L4)"); return; }

    const u_char *udp = ip + ihl;

    uint16_t src_port = rd16(udp + 0);
    uint16_t dst_port = rd16(udp + 2);
    uint16_t length   = rd16(udp + 4);
    uint16_t checksum = rd16(udp + 6);

    printf("\n=== UDP Header ===\n");
    printf("Source Port     : %u\n", src_port);
    printf("Destination Port: %u\n", dst_port);
    printf("Length          : %u bytes\n", length);
    printf("Checksum        : 0x%04x\n", checksum);

    printf("Service         : ");
    uint16_t svc = (dst_port < src_port ? dst_port : src_port);
    switch (svc) {
        case 53:   printf("DNS\n"); break;
        case 67:
        case 68:   printf("DHCP\n"); break;
        case 123:  printf("NTP\n"); break;
        case 5353: printf("mDNS (Multicast DNS)\n"); break;
        default:   printf("Unknown or Uncommon\n"); break;
    }
}

// === Display DNS Packet (IPv4/UDP, heuristic) ===
void parse_dns_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;

    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0800) return;

    if (!ensure_len(header, l2 + 20)) return;
    const u_char *ip = packet + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return;
    if (ip[9] != 0x11) return; // UDP
    if (!ensure_len(header, l2 + ihl + 8)) return;

    const u_char *udp = ip + ihl;
    uint16_t sp = rd16(udp + 0), dp = rd16(udp + 2);
    if (!(sp == 53 || dp == 53)) return;

    const u_char *dns = udp + 8;
    if (!ensure_len(header, (dns - packet) + 12)) { puts("(DNS) truncated"); return; }

    uint16_t transaction_id = rd16(dns + 0);
    uint16_t flags = rd16(dns + 2);
    uint16_t questions = rd16(dns + 4);

    printf("\n=== DNS Packet ===\n");
    printf("Transaction ID   : 0x%04x\n", transaction_id);
    printf("Flags            : 0x%04x\n", flags);
    printf("Questions        : %u\n", questions);

    // Minimal QNAME dump with bounds checks
    printf("Query Domain     : ");
    size_t idx = 12;
    size_t dns_off = (dns - packet);
    while (ensure_len(header, dns_off + idx + 1) && dns[idx] != 0) {
        uint8_t len = dns[idx++];
        if (len == 0 || len >= 63) break; // simple guard
        if (!ensure_len(header, dns_off + idx + len)) break;
        for (uint8_t i = 0; i < len; i++) putchar(dns[idx++]);
        if (dns[idx] != 0) putchar('.');
    }
    putchar('\n');
}

// === Display DHCP Packet (IPv4/UDP) ===
void parse_dhcp_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose < 2) return;

    size_t l2; uint16_t et; if (parse_l2(header, packet, &l2, &et) < 0) return;
    if (et != 0x0800) return;

    if (!ensure_len(header, l2 + 20)) return;
    const u_char *ip = packet + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return;
    if (ip[9] != 0x11) return; // UDP
    if (!ensure_len(header, l2 + ihl + 8)) return;

    const u_char *udp = ip + ihl;
    uint16_t sp = rd16(udp + 0), dp = rd16(udp + 2);
    if (!((sp == 67 || sp == 68) || (dp == 67 || dp == 68))) return;

    const u_char *dhcp = udp + 8;
    if (!ensure_len(header, (dhcp - packet) + 240)) { puts("(DHCP/BOOTP) truncated"); return; }

    uint32_t xid = rd32(dhcp + 4);
    const u_char *chaddr = dhcp + 28;

    printf("\n=== DHCP Packet ===\n");
    printf("Transaction ID   : 0x%08x\n", xid);
    printf("Client MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n",
           chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    printf("Your IP          : %u.%u.%u.%u\n", dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
}

// === Display Raw Packet in Hex ===
void print_raw_hex(const u_char *packet, size_t len) {
    if (g_verbose >= 3) {
        printf("\n=== Raw Hex Dump ===\n");
        for (size_t i = 0; i < len; i++) {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n--------------------------------------------------\n\n");
    }
}

// === Very brief summary for v=1 (with dynamic offsets) ===
void print_summary(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose != 1) return;

    size_t l2; uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0) { printf("[TRUNC] caplen=%u\n", header->caplen); return; }

    if (et == 0x0806) { // ARP
        if (!ensure_len(header, l2 + 28)) { printf("[ARP] caplen=%u (trunc)\n", header->caplen); return; }
        printf("[ARP] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d\n",
               header->len,
               packet[l2+14], packet[l2+15], packet[l2+16], packet[l2+17],
               packet[l2+24], packet[l2+25], packet[l2+26], packet[l2+27]);
        return;
    }

    if (et == 0x0800) { // IPv4
        if (!ensure_len(header, l2 + 20)) { printf("[IPv4] caplen=%u (trunc)\n", header->caplen); return; }
        const u_char *ip = packet + l2;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) { printf("[IPv4] invalid IHL\n"); return; }
        if (!ensure_len(header, l2 + ihl)) { printf("[IPv4] caplen=%u (trunc ihl)\n", header->caplen); return; }
        uint8_t proto = ip[9];

        const u_char *sip = ip + 12;
        const u_char *dip = ip + 16;

        if (proto == 0x06) { // TCP
            if (!ensure_len(header, l2 + ihl + 4)) { printf("[IPv4/TCP] caplen=%u (trunc)\n", header->caplen); return; }
            const u_char *tcp = ip + ihl;
            uint16_t sport = rd16(tcp + 0);
            uint16_t dport = rd16(tcp + 2);
            printf("[IPv4/TCP] len=%u  %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3], sport,
                   dip[0],dip[1],dip[2],dip[3], dport);
        } else if (proto == 0x11) { // UDP
            if (!ensure_len(header, l2 + ihl + 4)) { printf("[IPv4/UDP] caplen=%u (trunc)\n", header->caplen); return; }
            const u_char *udp = ip + ihl;
            uint16_t sport = rd16(udp + 0);
            uint16_t dport = rd16(udp + 2);
            printf("[IPv4/UDP] len=%u  %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3], sport,
                   dip[0],dip[1],dip[2],dip[3], dport);
        } else if (proto == 0x01) { // ICMP
            printf("[IPv4/ICMP] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3],
                   dip[0],dip[1],dip[2],dip[3]);
        } else {
            printf("[IPv4/0x%02x] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   proto, header->len,
                   sip[0],sip[1],sip[2],sip[3],
                   dip[0],dip[1],dip[2],dip[3]);
        }
        return;
    }

    // (IPv6 not handled yet)
    printf("[EtherType 0x%04x] len=%u\n", et, header->len);
}

// === Callback: Main Packet Parser ===
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    if (g_verbose == 1) {
        print_summary(header, packet);
        // no hex in v=1 (avoid confusing no-op)
        return;
    }

    size_t l2; uint16_t et;
    if (parse_l2(header, packet, &l2, &et) < 0) return;

    // v>=2: simple hierarchy display
    printf("Packet captured!\n");
    printf(" -> Length: %u bytes (caplen=%u)\n\n", header->len, header->caplen);

    // Ethernet Header
    printf("=== Ethernet Header ===\n");
    print_mac("Destination MAC : ", packet);
    print_mac("Source MAC      : ", packet + 6);
    if (g_verbose >= 2) printf("EtherType       : 0x%04x\n", et);

    // ARP
    if (et == 0x0806) {
        parse_arp(header, packet);
    }
    // IPv4
    else if (et == 0x0800) {
        if (!ensure_len(header, l2 + 20)) { puts("(IPv4) truncated"); return; }

        const u_char *ip = packet + l2;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) { puts("(IPv4) invalid IHL"); return; }
        if (!ensure_len(header, l2 + ihl)) { puts("(IPv4) truncated (ihl)"); return; }

        printf("\n=== IP Header (IPv4) ===\n");
        print_ip("Source IP       : ", ip + 12);
        print_ip("Destination IP  : ", ip + 16);

        uint8_t protocol = ip[9];
        printf("Protocol        : 0x%02x ", protocol);

        switch (protocol) {
            case 0x01:
                printf("(ICMP)\n");
                parse_icmp(header, packet);
                break;
            case 0x06:
                printf("(TCP)\n");
                parse_tcp(header, packet);
                break;
            case 0x11:
                printf("(UDP)\n");
                parse_udp(header, packet);

                // UDP -> detect higher-level protocols
                if (!ensure_len(header, l2 + ihl + 8)) break;
                {
                    const u_char *udp = ip + ihl;
                    uint16_t src_port = rd16(udp + 0);
                    uint16_t dst_port = rd16(udp + 2);
                    if (src_port == 53 || dst_port == 53)
                        parse_dns_packet(header, packet);
                    else if ((src_port == 67 || dst_port == 67) || (src_port == 68 || dst_port == 68))
                        parse_dhcp_packet(header, packet);
                }
                break;
            default:
                printf("(Unknown)\n");
        }
    } else {
        printf("Unknown/Unhandled EtherType, parsing skipped.\n");
    }

    // Hex dump only in v=3
    print_raw_hex(packet, header->caplen);
}

// === Usage ===
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s (-i <interface> | -o <pcapfile>) [-f \"bpf filter\"] [-v 1|2|3]\n"
        "  -i <iface>   Live capture interface\n"
        "  -o <file>    Read packets from pcap file (offline)\n"
        "  -f <expr>    BPF filter expression (e.g., \"tcp port 80 or arp\")\n"
        "  -v <level>   Verbosity: 1=summary, 2=synthetic (default), 3=full+hex\n",
        prog);
}

// === Apply BPF filter if provided ===
static int apply_filter(pcap_t *handle, const char *iface_or_null, const char *bpf) {
    if (!bpf) return 0;
    struct bpf_program fp;
    bpf_u_int32 net = 0, mask = 0;

    if (iface_or_null) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(iface_or_null, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "pcap_lookupnet failed on %s: %s (using 0.0.0.0/0)\n", iface_or_null, errbuf);
            net = 0; mask = 0;
        }
    } else {
        net = 0; mask = 0;
    }

    if (pcap_compile(handle, &fp, bpf, 1 /*optimize*/, mask) == -1) {
        fprintf(stderr, "pcap_compile failed for filter '%s': %s\n", bpf, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

// === Main Function ===
int main(int argc, char *argv[]) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = NULL;
    char *pcapfile = NULL;
    char *bpf = NULL;
    int opt;

    // Parse CLI
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'o': pcapfile = optarg; break;
            case 'f': bpf = optarg; break;
            case 'v':
                g_verbose = atoi(optarg);
                if (g_verbose < 1 || g_verbose > 3) {
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

    // Validate mode: exactly one of -i or -o
    if ((iface && pcapfile) || (!iface && !pcapfile)) {
        fprintf(stderr, "Error: specify exactly one of -i <iface> or -o <pcapfile>.\n");
        usage(argv[0]);
        return 1;
    }

    if (iface) {
        // Open live capture (snaplen 65535 to avoid payload truncation)
        handle = pcap_open_live(iface, 65535, 1 /*promisc*/, 1000 /*timeout ms*/, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening device %s: %s\n", iface, errbuf);
            return 1;
        }

        // Reject non-Ethernet link-layers early
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Unsupported link-layer (expecting Ethernet).\n");
            pcap_close(handle);
            return 1;
        }

        if (apply_filter(handle, iface, bpf) == -1) {
            pcap_close(handle);
            return 1;
        }

        printf("Live capture on %s (verbosity=%d)%s\n",
               iface, g_verbose, bpf ? " with filter" : "");
        if (bpf) printf("BPF: %s\n", bpf);

        int rc = pcap_loop(handle, -1, got_packet, NULL);
        if (rc == -1) fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
    } else {
        // Offline mode
        handle = pcap_open_offline(pcapfile, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening pcap file %s: %s\n", pcapfile, errbuf);
            return 1;
        }

        // Reject non-Ethernet link-layers early
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Unsupported link-layer (expecting Ethernet).\n");
            pcap_close(handle);
            return 1;
        }

        if (apply_filter(handle, NULL, bpf) == -1) {
            pcap_close(handle);
            return 1;
        }

        printf("Offline read from %s (verbosity=%d)%s\n",
               pcapfile, g_verbose, bpf ? " with filter" : "");
        if (bpf) printf("BPF: %s\n", bpf);

        int rc = pcap_loop(handle, -1, got_packet, NULL);
        if (rc == -1) fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
    }

    return 0;
}
