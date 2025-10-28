#ifndef DECODE_H
#define DECODE_H

#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdint.h>

/* Global verbosity (set in main.c) */
extern int g_verbose;

/* L2 */
int parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len);
void print_mac(const unsigned char *m);

/* L3 */
void handle_ipv4(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off);
void handle_ipv6(const struct pcap_pkthdr *h, const unsigned char *p, int ip6_off);
void handle_arp(const struct pcap_pkthdr *h, const unsigned char *p, int off);

/* L4 */
void handle_icmp(const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_icmp6(const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_tcp(const struct pcap_pkthdr *h, const unsigned char *p, int off);

/* App (called from UDP/TCP when ports match) */
void try_dns(const unsigned char *p, int len);
void try_dhcp(const unsigned char *p, int len);
void try_http(const unsigned char *p, int len);
void try_ftp(const unsigned char *p, int len);
void try_smtp(const unsigned char *p, int len);

/* Helpers */
void hexdump(const unsigned char *p, int len, int max_bytes);
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p);

/* v=3 helpers */
void v3printf(int depth, const char *fmt, ...);
void v3hexdump(const unsigned char *p, int len, int max_bytes, int depth);

#endif /* DECODE_H */
