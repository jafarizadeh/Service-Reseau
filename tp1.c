#include <pcap.h>
#include <stdio.h>

// Define the callback function
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured!\n");
    printf(" -> Length: %d bytes\n", header->len);

        // Print each byte in hex format
    for (int i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]); // %02x → 2-digit hex, padded with zero

        // Add newline every 16 bytes
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
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
