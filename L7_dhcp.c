#include "decode.h"
#include "bootp.h"
#include <stdio.h>
#include <arpa/inet.h>

/* Décodage DHCP/BOOTP :
   - parse l’en-tête BOOTP fixe,
   - puis lit quelques options DHCP clés (53/50/51/54).
   Objectif : affichage pédagogique, sans décodage exhaustif. */
void try_dhcp(const unsigned char *p, int len)
{

    /* l’en-tête BOOTP a une taille fixe (236 octets). */
    if (len < (int)sizeof(struct bootp)) {
        printf("  DHCP/BOOTP (truncated)\n");
        return;
    }

    const struct bootp *bp = (const struct bootp *)p;

    printf("  DHCP/BOOTP: op=%u htype=%u hlen=%u xid=0x%08x\n",
           (unsigned)bp->bp_op, (unsigned)bp->bp_htype, (unsigned)bp->bp_hlen,
           (unsigned)ntohl(bp->bp_xid));

    /* yiaddr = adresse IP attribuée au client dans les réponses DHCP. */
    char yi[32] = {0};
    inet_ntop(AF_INET, &bp->bp_yiaddr, yi, sizeof(yi));
    printf("    yiaddr=%s\n", yi);

    /* chaddr = MAC du client (lecture limitée à 6 octets pour Ethernet). */
    if (bp->bp_hlen == 6) {
        printf("    chaddr=");
        for (int i = 0; i < 6; i++)
            printf("%s%02x", (i ? ":" : ""), bp->bp_chaddr[i]);
        printf("\n");
    }

    if (g_verbose == 3) {
        /* En v=3 on affiche aussi les champs BOOTP secondaires utiles. */
        char ci[32]={0}, si[32]={0}, gi[32]={0};
        inet_ntop(AF_INET, &bp->bp_ciaddr, ci, sizeof(ci));
        inet_ntop(AF_INET, &bp->bp_siaddr, si, sizeof(si));
        inet_ntop(AF_INET, &bp->bp_giaddr, gi, sizeof(gi));
        printf("    secs=%u flags=0x%04x\n",
               (unsigned)ntohs(bp->bp_secs), (unsigned)ntohs(bp->bp_flags));
        printf("    ciaddr=%s siaddr=%s giaddr=%s\n", ci, si, gi);
    }

    /* Les options DHCP commencent après l’en-tête BOOTP fixe (236 octets),
       suivi du magic cookie (4 octets). */
    int opt_off = 236;

    /* Vérification du magic cookie DHCP = 0x63825363. */
    if (len < opt_off + 4) { printf("    (no DHCP magic cookie)\n"); return; }
    if (p[opt_off] != 0x63 || p[opt_off+1] != 0x82 || p[opt_off+2] != 0x53 || p[opt_off+3] != 0x63) {
        printf("    (no DHCP magic cookie)\n"); return;
    }
    int o = opt_off + 4;

    /* Parse TLV (Tag-Length-Value) : on s’arrête dès qu’on a les options clés. */
    int seen_msg = 0, seen_reqip = 0, seen_lease = 0, seen_svr = 0;

    while (o < len) {
        uint8_t tag = p[o++];
        if (tag == DHCP_OPT_END) break;
        if (tag == DHCP_OPT_PAD) continue;
        if (o >= len) break;

        uint8_t olen = p[o++];
        if (o + olen > len) break;

        if (tag == DHCP_OPT_MSG_TYPE && olen == 1) {
            uint8_t mt = p[o];
            const char *name = "UNKNOWN";
            if (mt == 1) name = "DISCOVER";
            else if (mt == 2) name = "OFFER";
            else if (mt == 3) name = "REQUEST";
            else if (mt == 4) name = "DECLINE";
            else if (mt == 5) name = "ACK";
            else if (mt == 6) name = "NAK";
            else if (mt == 7) name = "RELEASE";
            else if (mt == 8) name = "INFORM";
            printf("    opt53 msg-type=%u (%s)\n", (unsigned)mt, name);
            seen_msg = 1;
        } else if (tag == DHCP_OPT_REQ_IP && olen == 4) {
            char buf[32] = {0};
            inet_ntop(AF_INET, p + o, buf, sizeof(buf));
            printf("    opt50 requested-ip=%s\n", buf);
            seen_reqip = 1;
        } else if (tag == DHCP_OPT_LEASE && olen == 4) {
            unsigned int secs = (unsigned int)((p[o] << 24) | (p[o+1] << 16) | (p[o+2] << 8) | p[o+3]);
            printf("    opt51 lease=%us\n", secs);
            seen_lease = 1;
        } else if (tag == DHCP_OPT_SERVER_ID && olen == 4) {
            char buf[32] = {0};
            inet_ntop(AF_INET, p + o, buf, sizeof(buf));
            printf("    opt54 server-id=%s\n", buf);
            seen_svr = 1;
        }

        o += olen;
        if (seen_msg && seen_reqip && seen_lease && seen_svr) break;
    }
}
