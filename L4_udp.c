#include "decode.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "l7.h"



/* Handler UDP :
   - décode l’en-tête UDP (taille fixe),
   - affiche selon la verbosité,
   - tente une détection L7 simple par ports (DNS/DHCP). */
void handle_udp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    /* vérifier qu'on a au moins l'en-tête UDP complet. */
    if ((int)h->caplen < off + (int)sizeof(struct udphdr)) return;

    const struct udphdr *uh = (const struct udphdr *)(p + off);

    /* Accès portable aux champs UDP via macros (compat.h). */
    unsigned short sp = UDP_SPORT(uh);
    unsigned short dp = UDP_DPORT(uh);
    unsigned short ulen = UDP_LEN(uh);

    if (g_verbose == 3) {
        printf("UDP:\n");
        printf("  src-port=%u dst-port=%u length=%u checksum=0x%04x\n",
               sp, dp, ulen, UDP_SUM(uh));
    } else if (g_verbose >= 2) {
        printf("UDP: %u -> %u len=%u\n", sp, dp, ulen);
    }

    /* Début du payload après l'en-tête UDP. */
    const unsigned char *pl = p + off + (int)sizeof(struct udphdr);
    int plen = (int)h->caplen - (int)(pl - p);
    if (plen < 0) plen = 0;

    /* Heuristique L7 par port : DNS=53, DHCP=67/68. */
    if (dp == 53 || sp == 53)           try_dns(pl, plen);
    if (dp == 67 || dp == 68 || sp == 67 || sp == 68) try_dhcp(pl, plen);
}
