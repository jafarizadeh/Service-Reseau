#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured!\n");
    printf(" -> Length: %d bytes\n\n", header->len);

    printf("=== Ethernet Header ===\n");

    printf("Destination MAC : ");
    for (int i = 0; i < 6; i++) printf("%02x ", packet[i]);
    printf("\n");

    printf("Source MAC      : ");
    for (int i = 6; i < 12; i++) printf("%02x ", packet[i]);
    printf("\n");

    printf("EtherType       : %02x %02x\n", packet[12], packet[13]);

    // ARP: EtherType == 08 06
    if (packet[12] == 0x08 && packet[13] == 0x06) {
        printf("\n=== ARP Packet ===\n");

        printf("Sender MAC      : ");
        for (int i = 22; i < 28; i++) printf("%02x ", packet[i]);
        printf("\n");

        printf("Sender IP       : %d.%d.%d.%d\n", packet[28], packet[29], packet[30], packet[31]);

        printf("Target MAC      : ");
        for (int i = 32; i < 38; i++) printf("%02x ", packet[i]);
        printf("\n");

        printf("Target IP       : %d.%d.%d.%d\n", packet[38], packet[39], packet[40], packet[41]);
    }

    // IPv4: EtherType == 08 00
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("\n=== IP Header (if IPv4) ===\n");

        printf("Source IP       : %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
        printf("Destination IP  : %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);

        printf("Protocol        : %02x ", packet[23]);
        if (packet[23] == 0x01) {
            printf("(ICMP)\n");

            // ICMP Header starts after IP header (assumed 20 bytes)
            printf("\n=== ICMP Header ===\n");
            printf("Type            : %d\n", packet[34]);
            printf("Code            : %d\n", packet[35]);
            printf("Checksum        : %02x %02x\n", packet[36], packet[37]);

        } else if (packet[23] == 0x06)
            printf("(TCP)\n");
        else if (packet[23] == 0x11)
            printf("(UDP)\n");
        else
            printf("(Unknown)\n");
    }

    printf("\n=== Raw Hex Dump ===\n");
    for (int i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n--------------------------------------------------\n\n");
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
