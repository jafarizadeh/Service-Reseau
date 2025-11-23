
#ifndef L7_H
#define L7_H

#include <pcap/pcap.h>  

/* App-level decoders (called from L4) */
void try_dns  (const unsigned char *p, int len);
void try_dhcp (const unsigned char *p, int len);
void try_http (const unsigned char *p, int len);
void try_ftp  (const unsigned char *p, int len);
void try_smtp (const unsigned char *p, int len);

#endif
