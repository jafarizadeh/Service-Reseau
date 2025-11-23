#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

/* Valeurs de repli au cas où certaines constantes ND ne sont pas définies
   selon la plateforme / version des en-têtes. */
#ifndef ND_NEIGHBOR_SOLICIT
#define ND_NEIGHBOR_SOLICIT 135
#endif
#ifndef ND_NEIGHBOR_ADVERT
#define ND_NEIGHBOR_ADVERT 136
#endif

/* Portabilité ICMPv4 : les structures/champs diffèrent entre Linux et BSD/macOS.
   On unifie via macros pour garder un code unique. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define ICMPHDR    struct icmp
  #define ICMP_TYPE(h) ((h)->icmp_type)
  #define ICMP_CODE(h) ((h)->icmp_code)
#else
  #define ICMPHDR    struct icmphdr
  #define ICMP_TYPE(h) ((h)->type)
  #define ICMP_CODE(h) ((h)->code)
#endif

/* Handler ICMPv4 */
void handle_icmp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    
    /* type+code+checksum => au moins 4 octets nécessaires. */
    if ((int)h->caplen < off + 4) return;

    const ICMPHDR *ic = (const ICMPHDR *)(p + off);
    unsigned short cks = (unsigned short)((p[off+2] << 8) | p[off+3]);

    if (g_verbose == 3) {
        printf("ICMPv4:\n");
        printf("  type=%d code=%d checksum=0x%04x\n",
               (int)ICMP_TYPE(ic), (int)ICMP_CODE(ic), (unsigned)cks);

        /* Echo request (8) / reply (0) : id et seq sont juste après l'en-tête de base. */
        if ((ICMP_TYPE(ic) == 8 || ICMP_TYPE(ic) == 0) && (int)h->caplen >= off + 8) {
            unsigned short eid  = (unsigned short)((p[off+4] << 8) | p[off+5]);
            unsigned short eseq = (unsigned short)((p[off+6] << 8) | p[off+7]);
            printf("  echo-id=%u echo-seq=%u\n", (unsigned)eid, (unsigned)eseq);
        }
    } else {
        printf("ICMP: type=%d code=%d\n", (int)ICMP_TYPE(ic), (int)ICMP_CODE(ic));
    }
}

/* Handler ICMPv6 */
void handle_icmp6(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    /* vérifier la présence de l'en-tête ICMPv6 complet. */
    if ((int)h->caplen < off + (int)sizeof(struct icmp6_hdr)) return;

    const struct icmp6_hdr *ic6 = (const struct icmp6_hdr *)(p + off);
    unsigned char t = ic6->icmp6_type;
    unsigned char c = ic6->icmp6_code;

    printf("ICMPv6: type=%u code=%u", (unsigned)t, (unsigned)c);

    /* Echo req/rep ICMPv6 (128/129) — utile pour les tests ping6. */
    if (t == 128 || t == 129) printf(" (echo)");

    /* Neighbor Discovery : NS / NA — on essaie d'afficher la cible IPv6 si possible. */
    if (t == ND_NEIGHBOR_SOLICIT) {
        if ((int)h->caplen >= off + (int)sizeof(struct nd_neighbor_solicit)) {
            const struct nd_neighbor_solicit *ns = (const struct nd_neighbor_solicit *)(p + off);
            char tgt[64] = {0};
            inet_ntop(AF_INET6, &ns->nd_ns_target, tgt, sizeof(tgt));
            printf(" (ns target=%s)", tgt);
        }
    }
    
    else if (t == ND_NEIGHBOR_ADVERT) {
        if ((int)h->caplen >= off + (int)sizeof(struct nd_neighbor_advert)) {
            const struct nd_neighbor_advert *na = (const struct nd_neighbor_advert *)(p + off);
            char tgt[64] = {0};
            inet_ntop(AF_INET6, &na->nd_na_target, tgt, sizeof(tgt));
            printf(" (na target=%s)", tgt);
        }
    }

    printf("\n");

    if (g_verbose == 3) {
        unsigned short cks = ntohs(ic6->icmp6_cksum);
        printf("  checksum=0x%04x\n", (unsigned)cks);

        /* Echo id/seq pour ICMPv6. */
        if ((t == 128 || t == 129) && (int)h->caplen >= off + 8) {
            unsigned short eid  = (unsigned short)((p[off+4] << 8) | p[off+5]);
            unsigned short eseq = (unsigned short)((p[off+6] << 8) | p[off+7]);
            printf("  echo-id=%u echo-seq=%u\n", (unsigned)eid, (unsigned)eseq);
        }

        /* En v=3 on dump une partie du payload pour inspection. */
        const unsigned char *pl = p + off + (int)sizeof(struct icmp6_hdr);
        int plen = (int)h->caplen - (int)(pl - p);
        if (plen > 0) hexdump(pl, plen, 64);
    }
}
