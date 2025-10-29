#ifndef DECODE_H
#define DECODE_H

#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include "compat.h"
#include "bootp.h"

extern int g_verbose;

void hexdump(const unsigned char *p, int len, int max_bytes);
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p);
void print_mac(const unsigned char *m);


#endif /* DECODE_H */
