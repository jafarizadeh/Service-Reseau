#ifndef DECODE_H
#define DECODE_H

#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include "compat.h"
#include "bootp.h"

/* Indicateur global de verbosité (défini dans main.c).
   Permet aux handlers d'adapter l'affichage (v=1/2/3). */
extern int g_verbose;

/* === Couche 2 (L2) === */
/* parse_ethernet renvoie l'EtherType détecté et la longueur L2 (offset L3),
   en supportant éventuellement 802.1Q VLAN. */
int  parse_ethernet(const struct pcap_pkthdr *h, const unsigned char *p, int *eth_type, int *l2len);
void print_mac(const unsigned char *m);

/* === Couche 3 (L3) === */
/* Handlers L3 appelés selon EtherType :
   - ARP
   - IPv4
   - IPv6 */
void handle_arp (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_ipv4(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off);
void handle_ipv6(const struct pcap_pkthdr *h, const unsigned char *p, int ip_off);


/* === Couche 4 (L4) === */
/* Handlers transport appelés selon ip_p / next-header :
   ICMPv4, ICMPv6, UDP, TCP. */
void handle_icmp (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_icmp6(const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_udp  (const struct pcap_pkthdr *h, const unsigned char *p, int off);
void handle_tcp  (const struct pcap_pkthdr *h, const unsigned char *p, int off);

/* === Utilitaires === */
/* hexdump : affichage limité du payload en v=3.
   print_summary_line : ligne courte en v=1. */
void hexdump(const unsigned char *p, int len, int max_bytes);
void print_summary_line(const struct pcap_pkthdr *h, const unsigned char *p);

#endif
