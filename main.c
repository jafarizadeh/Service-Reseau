#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/ethernet.h>

#include "decode.h"

int g_verbose = 2;
static pcap_t *g_handle = NULL;

/* performance counters */
static unsigned long g_pkt_count = 0;
static unsigned long g_byte_count = 0;
static int g_started = 0;
static struct timeval g_t0, g_t1;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s (-i <iface> | -o <pcap>) [-f <bpf>] [-v 1|2|3]\n", prog);
}

static int apply_filter(pcap_t *h, const char *iface_or_null, const char *bpf) {
    if (!bpf) return 0;
    struct bpf_program fp;
    bpf_u_int32 net = 0, mask = 0;
    if (iface_or_null) {
        char eb[PCAP_ERRBUF_SIZE];
        if (pcap_lookupnet(iface_or_null, &net, &mask, eb) == -1) { net = 0; mask = 0; }
    }
    if (pcap_compile(h, &fp, bpf, 1, mask) == -1) return -1;
    if (pcap_setfilter(h, &fp) == -1) { pcap_freecode(&fp); return -1; }
    pcap_freecode(&fp);
    return 0;
}

static void on_sigint(int s) {
    (void)s;
    if (g_handle) pcap_breakloop(g_handle);
}

/* pcap callback: update perf counters first, then decode */

static void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    (void)user;

    if (g_verbose == 1) {
        print_summary_line(h, p);
        return;
    }

    int eth_type = 0, l2len = 0;
    if (parse_ethernet(h, p, &eth_type, &l2len) != 0) return;

    if (eth_type == ETHERTYPE_IP) {
        handle_ipv4(h, p, l2len);
    } else if (eth_type == ETHERTYPE_IPV6) {   // <-- add this line
        handle_ipv6(h, p, l2len);
    } else if (eth_type == ETHERTYPE_ARP) {
        handle_arp(h, p, l2len);
    } else {
        if (g_verbose >= 2)
            printf("Unknown EtherType: 0x%04x\n", eth_type);
    }
}


static void print_perf_summary(void) {
    printf("\n=== Performance summary ===\n");
    printf("packets=%lu bytes=%lu\n", g_pkt_count, g_byte_count);

    if (g_started) {
        double dur = (g_t1.tv_sec - g_t0.tv_sec)
                   + (g_t1.tv_usec - g_t0.tv_usec) / 1000000.0;
        if (dur < 0) dur = 0; /* just in case */
        printf("duration=%.3f s\n", dur);
        if (dur > 0) {
            double pps = g_pkt_count / dur;
            double mbit = (g_byte_count * 8.0) / (1000.0 * 1000.0);
            double mbitps = (dur > 0) ? (mbit / dur) : 0.0;
            printf("rate: %.1f pkt/s, %.2f Mbit/s\n", pps, mbitps);
        }
    }

    /* try to show pcap stats if available (live capture) */
    if (g_handle) {
        struct pcap_stat st;
        if (pcap_stats(g_handle, &st) == 0) {
            printf("pcap: ps_recv=%u ps_drop=%u ps_ifdrop=%u\n",
                   st.ps_recv, st.ps_drop, st.ps_ifdrop);
        }
    }
    printf("===========================\n");
}

int main(int argc, char **argv) {
    char *iface = NULL, *of = NULL, *bpf = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'o': of    = optarg; break;
        case 'f': bpf   = optarg; break;
        case 'v': g_verbose = atoi(optarg); break;
        default: usage(argv[0]); return 1;
        }
    }
    if (!!iface == !!of) { usage(argv[0]); return 1; }
    if (g_verbose < 1 || g_verbose > 3) g_verbose = 2;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (iface) g_handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    else       g_handle = pcap_open_offline(of, errbuf);

    if (!g_handle) { fprintf(stderr, "%s\n", errbuf); return 1; }

    if (pcap_datalink(g_handle) != DLT_EN10MB) {
        fprintf(stderr, "Only Ethernet is supported.\n");
        pcap_close(g_handle);
        return 1;
    }
    if (apply_filter(g_handle, iface, bpf) == -1) {
        fprintf(stderr, "Could not apply filter.\n");
        pcap_close(g_handle);
        return 1;
    }

    signal(SIGINT, on_sigint);
    if (pcap_loop(g_handle, -1, got_packet, NULL) == -1)
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(g_handle));

    /* always print perf summary at the end */
    print_perf_summary();

    pcap_close(g_handle);
    return 0;
}
