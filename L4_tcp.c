#include "decode.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "l7.h"


/* TCP compatibility (BSD/macOS vs Linux) */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  #define TCP_SPORT(t) ntohs((t)->th_sport)
  #define TCP_DPORT(t) ntohs((t)->th_dport)
  #define TCP_DOFF(t)  ((t)->th_off * 4)
  #define TCP_FLAG_SYN(t) ((t)->th_flags & TH_SYN)
  #define TCP_FLAG_ACK(t) ((t)->th_flags & TH_ACK)
  #define TCP_FLAG_FIN(t) ((t)->th_flags & TH_FIN)
  #define TCP_FLAG_RST(t) ((t)->th_flags & TH_RST)
  #define TCP_FLAG_PSH(t) ((t)->th_flags & TH_PUSH)
  #define TCP_FLAG_URG(t) ((t)->th_flags & TH_URG)
  #define TCP_SEQ(t)   ntohl((t)->th_seq)
  #define TCP_ACKN(t)  ntohl((t)->th_ack)
  #define TCP_WIN(t)   ntohs((t)->th_win)
  #define TCP_SUM(t)   ntohs((t)->th_sum)
  #define TCP_URP(t)   ntohs((t)->th_urp)
#else
  #define TCP_SPORT(t) ntohs((t)->source)
  #define TCP_DPORT(t) ntohs((t)->dest)
  #define TCP_DOFF(t)  ((t)->doff * 4)
  #define TCP_FLAG_SYN(t) ((t)->syn)
  #define TCP_FLAG_ACK(t) ((t)->ack)
  #define TCP_FLAG_FIN(t) ((t)->fin)
  #define TCP_FLAG_RST(t) ((t)->rst)
  #define TCP_FLAG_PSH(t) ((t)->psh)
  #define TCP_FLAG_URG(t) ((t)->urg)
  #define TCP_SEQ(t)   ntohl((t)->seq)
  #define TCP_ACKN(t)  ntohl((t)->ack_seq)
  #define TCP_WIN(t)   ntohs((t)->window)
  #define TCP_SUM(t)   ntohs((t)->check)
  #define TCP_URP(t)   ntohs((t)->urg_ptr)
#endif

/* TCP handler: prints flags and tries HTTP/FTP/SMTP by port */
void handle_tcp(const struct pcap_pkthdr *h, const unsigned char *p, int off)
{
    if ((int)h->caplen < off + (int)sizeof(struct tcphdr)) return;

    const struct tcphdr *th = (const struct tcphdr *)(p + off);
    unsigned short sp = TCP_SPORT(th);
    unsigned short dp = TCP_DPORT(th);
    int doff = TCP_DOFF(th);
    if ((int)h->caplen < off + doff) return;

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

    /* payload pointer */
    const unsigned char *pl = p + off + doff;
    int plen = (int)h->caplen - (int)(pl - p);
    if (plen < 0) plen = 0;

    /* L7 guesses by port */
    if (dp == 80 || sp == 80) try_http(pl, plen);
    if (dp == 21 || sp == 21) try_ftp(pl, plen);
    if (dp == 25 || sp == 25) try_smtp(pl, plen);
}
