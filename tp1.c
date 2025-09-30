#include <pcap.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    //  Check if user provided an interface name
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    dev = argv[1]; // get interface name from command line

    // Open the device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Device %s opened successfully for sniffing.\n", dev);

    //  Close the handle
    pcap_close(handle);
    return 0;
}
