#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   // getopt
#include <ctype.h>

static int g_verbose = 2; // default v=2

// === Utility: Print MAC Address ===
void print_mac(const char *label, const u_char *addr) {
    if (g_verbose >= 2) {
        printf("%s", label);
        for (int i = 0; i < 6; i++) printf("%02x ", addr[i]);
        printf("\n");
    }
}

// === Utility: Print IP Address ===
void print_ip(const char *label, const u_char *addr) {
    if (g_verbose >= 2) {
        printf("%s%d.%d.%d.%d\n", label, addr[0], addr[1], addr[2], addr[3]);
    }
}

// === Display ARP Packet ===
void parse_arp(const u_char *packet) {
    if (g_verbose >= 2) {
        printf("\n=== ARP Packet ===\n");
        print_mac("Sender MAC      : ", packet + 22);
        print_ip ("Sender IP       : ", packet + 28);
        print_mac("Target MAC      : ", packet + 32);
        print_ip ("Target IP       : ", packet + 38);
    }
}

// === Display ICMP Header ===
void parse_icmp(const u_char *packet) {
    if (g_verbose >= 2) {
        printf("\n=== ICMP Header ===\n");
        printf("Type            : %d\n", packet[34]);
        printf("Code            : %d\n", packet[35]);
        printf("Checksum        : %02x %02x\n", packet[36], packet[37]);
    }
}

// === Display TCP Header ===
void parse_tcp(const u_char *packet) {
    if (g_verbose >= 2) {
        printf("\n=== TCP Header ===\n");

        unsigned short src_port = (packet[34] << 8) | packet[35];
        unsigned short dst_port = (packet[36] << 8) | packet[37];
        unsigned int seq = (packet[38] << 24) | (packet[39] << 16) | (packet[40] << 8) | packet[41];
        unsigned int ack = (packet[42] << 24) | (packet[43] << 16) | (packet[44] << 8) | packet[45];
        unsigned char flags = packet[47];

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

        printf("Service         : ");
        switch (dst_port) {
            case 80:  printf("HTTP\n"); break;
            case 443: printf("HTTPS\n"); break;
            case 22:  printf("SSH\n"); break;
            case 25:  printf("SMTP\n"); break;
            case 110: printf("POP3\n"); break;
            case 143: printf("IMAP\n"); break;
            default:  printf("Unknown or Uncommon\n"); break;
        }
    }
}

// === Display UDP Header ===
void parse_udp(const u_char *packet) {
    if (g_verbose >= 2) {
        printf("\n=== UDP Header ===\n");

        unsigned short src_port = (packet[34] << 8) | packet[35];
        unsigned short dst_port = (packet[36] << 8) | packet[37];
        unsigned short length   = (packet[38] << 8) | packet[39];
        unsigned short checksum = (packet[40] << 8) | packet[41];

        printf("Source Port     : %u\n", src_port);
        printf("Destination Port: %u\n", dst_port);
        printf("Length          : %u bytes\n", length);
        printf("Checksum        : %04x\n", checksum);

        printf("Service         : ");
        switch (dst_port) {
            case 53:   printf("DNS\n"); break;
            case 67:
            case 68:   printf("DHCP\n"); break;
            case 123:  printf("NTP\n"); break;
            case 5353: printf("mDNS (Multicast DNS)\n"); break;
            default:   printf("Unknown or Uncommon\n"); break;
        }
    }
}

// === Display DNS Packet ===
void parse_dns_packet(const u_char *packet) {
    if (g_verbose >= 2) {
        const u_char *dns = packet + 42;

        unsigned short transaction_id = (dns[0] << 8) | dns[1];
        unsigned short flags = (dns[2] << 8) | dns[3];
        unsigned short questions = (dns[4] << 8) | dns[5];

        printf("\n=== DNS Packet ===\n");
        printf("Transaction ID   : 0x%04x\n", transaction_id);
        printf("Flags            : 0x%04x\n", flags);
        printf("Questions        : %d\n", questions);

        printf("Query Domain     : ");
        int index = 12;  // domain name starts at byte 12
        while (dns[index] != 0) {
            int len = dns[index++];
            for (int i = 0; i < len; i++) printf("%c", dns[index++]);
            if (dns[index] != 0) printf(".");
        }
        printf("\n");
    }
}

// === Display DHCP Packet ===
void parse_dhcp_packet(const u_char *packet) {
    if (g_verbose >= 2) {
        const u_char *dhcp = packet + 42;

        unsigned int xid = (dhcp[4] << 24) | (dhcp[5] << 16) | (dhcp[6] << 8) | dhcp[7];
        unsigned char client_mac[6];
        for (int i = 0; i < 6; i++) client_mac[i] = dhcp[28 + i];

        printf("\n=== DHCP Packet ===\n");
        printf("Transaction ID   : 0x%08x\n", xid);
        printf("Client MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n",
               client_mac[0], client_mac[1], client_mac[2],
               client_mac[3], client_mac[4], client_mac[5]);
        printf("Your IP          : %d.%d.%d.%d\n",
               dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
    }
}

// === Display Raw Packet in Hex ===
void print_raw_hex(const u_char *packet, int len) {
    if (g_verbose >= 3) {
        printf("\n=== Raw Hex Dump ===\n");
        for (int i = 0; i < len; i++) {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n--------------------------------------------------\n\n");
    }
}

// === Very brief summary for v=1 ===
void print_summary(const struct pcap_pkthdr *header, const u_char *packet) {
    if (g_verbose != 1) return;

    // EtherType
    unsigned short eth_type = ((unsigned short)packet[12] << 8) | packet[13];

    if (eth_type == 0x0806) { // ARP
        printf("[ARP] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d\n",
               header->len,
               packet[28], packet[29], packet[30], packet[31],
               packet[38], packet[39], packet[40], packet[41]);
        return;
    }

    if (eth_type == 0x0800) { // IPv4
        unsigned char proto = packet[23];
        // IPs
        const u_char *sip = packet + 26;
        const u_char *dip = packet + 30;

        if (proto == 0x06) { // TCP
            unsigned short sport = (packet[34] << 8) | packet[35];
            unsigned short dport = (packet[36] << 8) | packet[37];
            printf("[IPv4/TCP] len=%u  %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3], sport,
                   dip[0],dip[1],dip[2],dip[3], dport);
        } else if (proto == 0x11) { // UDP
            unsigned short sport = (packet[34] << 8) | packet[35];
            unsigned short dport = (packet[36] << 8) | packet[37];
            printf("[IPv4/UDP] len=%u  %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3], sport,
                   dip[0],dip[1],dip[2],dip[3], dport);
        } else if (proto == 0x01) { // ICMP
            unsigned char icmp_type = packet[34];
            printf("[IPv4/ICMP] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d  type=%u\n",
                   header->len,
                   sip[0],sip[1],sip[2],sip[3],
                   dip[0],dip[1],dip[2],dip[3],
                   icmp_type);
        } else {
            printf("[IPv4/0x%02x] len=%u  %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   proto, header->len,
                   sip[0],sip[1],sip[2],sip[3],
                   dip[0],dip[1],dip[2],dip[3]);
        }
        return;
    }

    // (IPv6 not handled in your current parser; will come in later phases)
    printf("[EtherType 0x%04x] len=%u\n", eth_type, header->len);
}

// === Callback: Main Packet Parser ===
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // v=1: summary (1-line)
    if (g_verbose == 1) {
        print_summary(header, packet);
        print_raw_hex(packet, header->len); // not print in v1
        return;
    }

    // v>=2: 
    printf("Packet captured!\n");
    printf(" -> Length: %d bytes\n\n", header->len);

    // Ethernet Header
    printf("=== Ethernet Header ===\n");
    print_mac("Destination MAC : ", packet);
    print_mac("Source MAC      : ", packet + 6);
    if (g_verbose >= 2) printf("EtherType       : %02x %02x\n", packet[12], packet[13]);

    // ARP
    if (packet[12] == 0x08 && packet[13] == 0x06) {
        parse_arp(packet);
    }
    // IPv4
    else if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("\n=== IP Header (IPv4) ===\n");
        print_ip("Source IP       : ", packet + 26);
        print_ip("Destination IP  : ", packet + 30);

        unsigned char protocol = packet[23];
        printf("Protocol        : %02x ", protocol);

        switch (protocol) {
            case 0x01:
                printf("(ICMP)\n");
                parse_icmp(packet);
                break;
            case 0x06:
                printf("(TCP)\n");
                parse_tcp(packet);
                break;
            case 0x11: {
                printf("(UDP)\n");
                parse_udp(packet);

                // UDP -> detect higher-level protocols
                unsigned short src_port = (packet[34] << 8) | packet[35];
                unsigned short dst_port = (packet[36] << 8) | packet[37];
                if (src_port == 53 || dst_port == 53)
                    parse_dns_packet(packet);
                else if ((src_port == 67 || dst_port == 67) || (src_port == 68 || dst_port == 68))
                    parse_dhcp_packet(packet);
                break;
            }
            default:
                printf("(Unknown)\n");
        }
    } else {
        printf("Unknown EtherType, parsing skipped.\n");
    }

    // Hex dump 
    print_raw_hex(packet, header->len);
}

// === Usage ===
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -i <interface> [-v 1|2|3]\n"
        "  -i <iface>   Live capture interface (required)\n"
        "  -v <level>   Verbosity level: 1=summary, 2=synthetic (default), 3=full+hex\n",
        prog);
}

// === Main Function ===
int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *iface = NULL;
    int opt;

    // Parse CLI: -i (required), -v (optional)
    while ((opt = getopt(argc, argv, "i:v:")) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
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

    if (!iface) {
        fprintf(stderr, "Error: -i <interface> is required.\n");
        usage(argv[0]);
        return 1;
    }

    // Open live capture 
    handle = pcap_open_live(iface, 65535 /*snaplen*/, 1 /*promisc*/, 1000 /*timeout ms*/, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", iface, errbuf);
        return 1;
    }

    printf("Waiting for a packet on interface %s (verbosity=%d)...\n", iface, g_verbose);
    // just one packet
    pcap_loop(handle, 1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
