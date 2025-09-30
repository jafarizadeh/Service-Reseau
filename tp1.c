#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "en0"; // change to your actual interface name

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Device %s opened successfully for sniffing.\n", dev);

    pcap_close(handle);
    return 0;
}
