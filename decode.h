#ifndef DECODE_H
#define DECODE_H

#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include "compat.h"
#include "bootp.h"

/* global verbose flag (defined in main.c) */
extern int g_verbose;

/* L2 */
int  parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len);
void print_mac(const unsigned char *m);

/* L3 */
void handle_arp (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_ipv4(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off);

/* L4 */
void handle_icmp (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_icmp6(const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_udp  (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_tcp  (const struct pcap_pkthdr *h, const unsigned char *p, int off);

/* utils */
void hexdump(const unsigned char *p, int len, int max_bytes);
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p);

#endif 
