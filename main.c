#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "decode.h"

int g_verbose = 2;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s (-i <iface> | -o <pcap>) [-f <bpf>] [-v 1|2|3]\n", prog);
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

    (void)bpf;
    fprintf(stderr, "Args OK. (stage 2)\n");
    return 0;
}
