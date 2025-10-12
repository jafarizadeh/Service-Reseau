#include <pcap.h>
#include <stdio.h>

// === Utility: Print MAC Address ===
void print_mac(const char *label, const u_char *addr) {
    printf("%s", label);
    for (int i = 0; i < 6; i++)
        printf("%02x ", addr[i]);
    printf("\n");
}

// === Utility: Print IP Address ===
void print_ip(const char *label, const u_char *addr) {
    printf("%s%d.%d.%d.%d\n", label, addr[0], addr[1], addr[2], addr[3]);
}

// === Display ARP Packet ===
void parse_arp(const u_char *packet) {
    printf("\n=== ARP Packet ===\n");
    print_mac("Sender MAC      : ", packet + 22);
    print_ip("Sender IP       : ", packet + 28);
    print_mac("Target MAC      : ", packet + 32);
    print_ip("Target IP       : ", packet + 38);
}

// === Display ICMP Header ===
void parse_icmp(const u_char *packet) {
    printf("\n=== ICMP Header ===\n");
    printf("Type            : %d\n", packet[34]);
    printf("Code            : %d\n", packet[35]);
    printf("Checksum        : %02x %02x\n", packet[36], packet[37]);
}

// === Display TCP Header ===
void parse_tcp(const u_char *packet) {
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

// === Display UDP Header ===
void parse_udp(const u_char *packet) {
    printf("\n=== UDP Header ===\n");
    unsigned short src_port = (packet[34] << 8) | packet[35];
    unsigned short dst_port = (packet[36] << 8) | packet[37];
    unsigned short length    = (packet[38] << 8) | packet[39];
    unsigned short checksum  = (packet[40] << 8) | packet[41];

    printf("Source Port     : %u\n", src_port);
    printf("Destination Port: %u\n", dst_port);
    printf("Length          : %u bytes\n", length);
    printf("Checksum        : %04x\n", checksum);

    printf("Service         : ");
    switch (dst_port) {
        case 53:   printf("DNS\n"); break;
        case 123:  printf("NTP\n"); break;
        case 5353: printf("mDNS (Multicast DNS)\n"); break;
        default:   printf("Unknown or Uncommon\n"); break;
    }
}

// === Display Raw Packet ===
void print_raw_hex(const u_char *packet, int len) {
    printf("\n=== Raw Hex Dump ===\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n--------------------------------------------------\n\n");
}

// === Callback: Main Packet Parser ===
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured!\n");
    printf(" -> Length: %d bytes\n\n", header->len);

    printf("=== Ethernet Header ===\n");
    print_mac("Destination MAC : ", packet);
    print_mac("Source MAC      : ", packet + 6);
    printf("EtherType       : %02x %02x\n", packet[12], packet[13]);

    // ARP
    if (packet[12] == 0x08 && packet[13] == 0x06) {
        parse_arp(packet);
    }

    // IPv4
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("\n=== IP Header (if IPv4) ===\n");
        print_ip("Source IP       : ", packet + 26);
        print_ip("Destination IP  : ", packet + 30);

        printf("Protocol        : %02x ", packet[23]);
        switch (packet[23]) {
            case 0x01:
                printf("(ICMP)\n");
                parse_icmp(packet);
                break;
            case 0x06:
                printf("(TCP)\n");
                parse_tcp(packet);
                break;
            case 0x11:
                printf("(UDP)\n");
                parse_udp(packet);
                break;
            default:
                printf("(Unknown)\n");
        }
    }

    print_raw_hex(packet, header->len);
}

// === Main Function ===
int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Waiting for a packet on interface %s...\n", dev);
    pcap_loop(handle, 1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
