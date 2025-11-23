#include "decode.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "l7.h"


/* Handler TCP :
   - décode l’en-tête TCP (taille variable via Data Offset),
   - affiche selon la verbosité,
   - tente une détection L7 simple par ports (HTTP/FTP/SMTP).
   Remarque : pas de réassemblage de flux TCP (analyse paquet par paquet). */
void handle_tcp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    /* vérifier qu'on a au moins l'en-tête TCP minimal. */
    if ((int)h->caplen < off + (int)sizeof(struct tcphdr)) return;

    const struct tcphdr *th = (const struct tcphdr *)(p + off);

    /* Accès portable aux champs TCP via macros (compat.h). */
    unsigned short sp = TCP_SPORT(th);
    unsigned short dp = TCP_DPORT(th);

    /* Data Offset (taille réelle de l'en-tête TCP) en octets. */
    int doff = TCP_DOFF(th);

    /* Sécurité : l'en-tête peut contenir des options => vérifier la longueur capturée. */
    if ((int)h->caplen < off + doff) return;

    /* Affichage détaillé en v=3, résumé en v=2. */
    if (g_verbose == 3) {
        unsigned int opts = (doff > 20) ? (doff - 20) : 0;
        printf("TCP:\n");
        printf("  src-port=%u dst-port=%u\n", sp, dp);
        printf("  seq=%u ack=%u hdr-len=%d\n", TCP_SEQ(th), TCP_ACKN(th), doff);
        printf("  flags%s%s%s%s%s%s\n",
               TCP_FLAG_SYN(th) ? " SYN" : "",
               TCP_FLAG_ACK(th) ? " ACK" : "",
               TCP_FLAG_FIN(th) ? " FIN" : "",
               TCP_FLAG_RST(th) ? " RST" : "",
               TCP_FLAG_PSH(th) ? " PSH" : "",
               TCP_FLAG_URG(th) ? " URG" : "");
        printf("  window=%u checksum=0x%04x urgptr=%u\n",
               TCP_WIN(th), TCP_SUM(th), TCP_URP(th));
        if (opts) printf("  options-bytes=%u\n", opts);
    } else if (g_verbose >= 2) {
        printf("TCP: %u -> %u", sp, dp);
        if (TCP_FLAG_SYN(th)) printf(" SYN");
        if (TCP_FLAG_ACK(th)) printf(" ACK");
        if (TCP_FLAG_FIN(th)) printf(" FIN");
        if (TCP_FLAG_RST(th)) printf(" RST");
        if (TCP_FLAG_PSH(th)) printf(" PSH");
        if (TCP_FLAG_URG(th)) printf(" URG");
        printf("\n");
    }

    /* Début du payload après l'en-tête TCP (doff). */
    const unsigned char *pl = p + off + doff;
    int plen = (int)h->caplen - (int)(pl - p);
    if (plen < 0) plen = 0;

    /* Heuristique L7 par port (simple et pédagogique). */
    if (dp == 80 || sp == 80) try_http(pl, plen);
    if (dp == 21 || sp == 21) try_ftp(pl, plen);
    if (dp == 25 || sp == 25) try_smtp(pl, plen);
}
