#include "decode.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* Lecteurs big-endian (réseau) pour champs DNS. */
static unsigned short rd16(const unsigned char *b) {
    return (unsigned short)((b[0] << 8) | b[1]);
}
static unsigned int rd32(const unsigned char *b) {
    return (unsigned int)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

/* Lecture d'un nom DNS avec compression (RFC1035) :
   - support des pointeurs 0xC0xx,
   - limite le nombre de sauts pour éviter les boucles.
   Retourne 0 si OK, sinon -1. */
static int dns_read_name(const unsigned char *msg, int msglen, int off,
                         char *out, int outsz, int *consumed)
{
    int o = off, outpos = 0, jumped = 0, jumps = 0;
    if (consumed) *consumed = 0;

    while (o >= 0 && o < msglen) {
        unsigned char len = msg[o];
        if (len == 0) { /* fin de nom */
            if (!jumped && consumed) *consumed = (o - off) + 1;
            if (outpos == 0) { out[0] = '.'; out[1] = '\0'; }
            else out[outpos] = '\0';
            return 0;
        }
        if ((len & 0xC0) == 0xC0) { /* pointeur de compression */
            if (o + 1 >= msglen) return -1;
            int ptr = ((len & 0x3F) << 8) | msg[o + 1];
            if (!jumped && consumed) *consumed = (o - off) + 2;
            o = ptr; jumped = 1;
            if (++jumps > 10) return -1; /* anti-boucle */
        } else { /* label classique */
            o++;
            if (o + len > msglen) return -1;
            if (outpos && outpos < outsz - 1) out[outpos++] = '.';
            for (int i = 0; i < len && outpos < outsz - 1; i++) {
                unsigned char c = msg[o + i];
                out[outpos++] = (c >= 32 && c <= 126) ? (char)c : '.';
            }
            o += len;
        }
    }
    return -1;
}

void try_dns(const unsigned char *p, int len)
{
    /* en-tête DNS minimal = 12 octets. */
    if (len < 12) { printf("  DNS (truncated)\n"); return; }

    int i = 0;
    unsigned short id = rd16(p + i); i += 2;
    unsigned short flags = rd16(p + i); i += 2;
    unsigned short qd = rd16(p + i); i += 2;
    unsigned short an = rd16(p + i); i += 2;
    unsigned short ns = rd16(p + i); i += 2;
    unsigned short ar = rd16(p + i); i += 2;

    if (g_verbose == 3) {
        /* Décomposition des flags DNS pour affichage détaillé. */
        unsigned short fl = flags;
        unsigned int QR    = (fl >> 15) & 1;
        unsigned int OPC   = (fl >> 11) & 0xF;
        unsigned int AA    = (fl >> 10) & 1;
        unsigned int TC    = (fl >> 9)  & 1;
        unsigned int RD    = (fl >> 8)  & 1;
        unsigned int RA    = (fl >> 7)  & 1;
        unsigned int Z     = (fl >> 4)  & 0x7;
        unsigned int RCODE =  fl        & 0xF;

        printf("  DNS:\n");
        printf("    id=0x%04x\n", id);
        printf("    flags: QR=%u OPCODE=%u AA=%u TC=%u RD=%u RA=%u Z=%u RCODE=%u\n",
               QR, OPC, AA, TC, RD, RA, Z, RCODE);
        printf("    counts: QD=%u AN=%u NS=%u AR=%u\n",
               (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
    } else {
        printf("  DNS: id=0x%04x qd=%u an=%u\n", id, (unsigned)qd, (unsigned)an);
        (void)flags; (void)ns; (void)ar;
    }

    /* Pour rester lisible (TP), on décode au plus 1 question. */
    if (qd > 0) {
        char qname[256];
        int consumed = 0;
        if (dns_read_name(p, len, i, qname, sizeof(qname), &consumed) == 0) {
            i += consumed;
            if (i + 4 <= len) {
                unsigned short qtype  = rd16(p + i); i += 2;
                unsigned short qclass = rd16(p + i); i += 2;
                printf("    Q: %s  type=%u class=%u\n",
                       qname, (unsigned)qtype, (unsigned)qclass);
            } else return;
        } else return;
    }

    /* Idem : on décode au plus 1 réponse (A/AAAA/CNAME). */
    if (an > 0) {
        char name[256];
        int consumed = 0;
        if (dns_read_name(p, len, i, name, sizeof(name), &consumed) != 0) return;
        i += consumed;

        /* RR minimal = type(2)+class(2)+ttl(4)+rdlen(2). */
        if (i + 10 > len) return;
        unsigned short type   = rd16(p + i); i += 2;
        unsigned short aclass = rd16(p + i); i += 2;
        unsigned int   ttl    = rd32(p + i); i += 4;
        unsigned short rdlen  = rd16(p + i); i += 2;
        if (i + rdlen > len) return;

        printf("    A: %s  type=%u class=%u ttl=%u ", name, (unsigned)type, (unsigned)aclass, ttl);

        if (type == 1 && rdlen == 4) { /* A */
            printf("addr=%u.%u.%u.%u\n", p[i], p[i+1], p[i+2], p[i+3]);
        } else if (type == 28 && rdlen == 16) { /* AAAA */
            char buf[64] = {0};
            inet_ntop(AF_INET6, p + i, buf, sizeof(buf));
            printf("addr=%s\n", buf);
        } else if (type == 5) { /* CNAME */
            char cname[256]; int cused = 0;
            if (dns_read_name(p, len, i, cname, sizeof(cname), &cused) == 0)
                printf("cname=%s\n", cname);
            else
                printf("rdata(%u bytes)\n", (unsigned)rdlen);
        } else { /* autres types non détaillés */
            printf("rdata(%u bytes)\n", (unsigned)rdlen);
        }
    }
}
