#ifndef COMPAT_H
#define COMPAT_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

/* Ce fichier regroupe des macros de portabilité.
   Objectif : masquer les différences de noms de champs entre Linux et BSD/macOS,
   afin de garder un code unique dans les handlers L4/L3. */

/* Accès aux flags TCP (BSD : th_flags / Linux : champs bitfields). */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define TCP_FLAG_SYN(th) ((th)->th_flags & TH_SYN)
#  define TCP_FLAG_ACK(th) ((th)->th_flags & TH_ACK)
#  define TCP_FLAG_FIN(th) ((th)->th_flags & TH_FIN)
#  define TCP_FLAG_RST(th) ((th)->th_flags & TH_RST)
#  define TCP_FLAG_PSH(th) ((th)->th_flags & TH_PUSH)
#  define TCP_FLAG_URG(th) ((th)->th_flags & TH_URG)
#else
#  define TCP_FLAG_SYN(th) ((th)->syn)
#  define TCP_FLAG_ACK(th) ((th)->ack)
#  define TCP_FLAG_FIN(th) ((th)->fin)
#  define TCP_FLAG_RST(th) ((th)->rst)
#  define TCP_FLAG_PSH(th) ((th)->psh)
#  define TCP_FLAG_URG(th) ((th)->urg)
#endif

/* ICMPv4 : type/code (BSD : struct icmp / Linux : struct icmphdr). */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define ICMPHDR struct icmp
#  define ICMP_TYPE(h) ((h)->icmp_type)
#  define ICMP_CODE(h) ((h)->icmp_code)
#else
#  define ICMPHDR struct icmphdr
#  define ICMP_TYPE(h) ((h)->type)
#  define ICMP_CODE(h) ((h)->code)
#endif

/* UDP : helpers pour ports/longueur/checksum selon la plateforme. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define UDP_SPORT(u) ntohs((u)->uh_sport)
#  define UDP_DPORT(u) ntohs((u)->uh_dport)
#  define UDP_LEN(u)   ntohs((u)->uh_ulen)
#  define UDP_SUM(u)   ntohs((u)->uh_sum)
#else
#  define UDP_SPORT(u) ntohs((u)->source)
#  define UDP_DPORT(u) ntohs((u)->dest)
#  define UDP_LEN(u)   ntohs((u)->len)
#  define UDP_SUM(u)   ntohs((u)->check)
#endif

/* TCP : helpers pour ports, taille d'en-tête (doff), seq/ack, fenêtre, checksum, urgptr. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define TCP_SPORT(t) ntohs((t)->th_sport)
#  define TCP_DPORT(t) ntohs((t)->th_dport)
#  define TCP_DOFF(t)  ((t)->th_off * 4)
#  define TCP_SEQ(t)   ntohl((t)->th_seq)
#  define TCP_ACKN(t)  ntohl((t)->th_ack)
#  define TCP_WIN(t)   ntohs((t)->th_win)
#  define TCP_SUM(t)   ntohs((t)->th_sum)
#  define TCP_URP(t)   ntohs((t)->th_urp)
#else
#  define TCP_SPORT(t) ntohs((t)->source)
#  define TCP_DPORT(t) ntohs((t)->dest)
#  define TCP_DOFF(t)  ((t)->doff * 4)
#  define TCP_SEQ(t)   ntohl((t)->seq)
#  define TCP_ACKN(t)  ntohl((t)->ack_seq)
#  define TCP_WIN(t)   ntohs((t)->window)
#  define TCP_SUM(t)   ntohs((t)->check)
#  define TCP_URP(t)   ntohs((t)->urg_ptr)
#endif

#endif
