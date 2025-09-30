#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured!\n");
    printf(" -> Length: %d bytes\n\n", header->len);

    printf("=== Ethernet Header ===\n");

    // Destination MAC (bytes 0–5)
    printf("Destination MAC : ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    // Source MAC (bytes 6–11)
    printf("Source MAC      : ");
    for (int i = 6; i < 12; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    // EtherType (bytes 12–13)
    printf("EtherType       : %02x %02x\n", packet[12], packet[13]);

    printf("\n=== IP Header (if IPv4) ===\n");

    // Basic assumption: if EtherType is 0x08 00, it's IPv4
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        // Source IP (bytes 26–29)
        printf("Source IP       : %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);

        // Destination IP (bytes 30–33)
        printf("Destination IP  : %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);

        // Protocol (byte 23)
        printf("Protocol        : %02x ", packet[23]);
        if (packet[23] == 0x01)
            printf("(ICMP)\n");
        else if (packet[23] == 0x06)
            printf("(TCP)\n");
        else if (packet[23] == 0x11)
            printf("(UDP)\n");
        else
            printf("(Unknown)\n");
    } else {
        printf("Not an IPv4 packet. Skipping IP info.\n");
    }

    printf("\n=== Raw Hex Dump ===\n");

    for (int i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

 
int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    // Read interface from user input
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    dev = argv[1];

    // Open the interface
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Print status
    printf("Waiting for a packet on interface %s...\n", dev);

    // Start packet capture (1 packet only)
    pcap_loop(handle, 1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
