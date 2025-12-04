#ifndef BOOTP_LOCAL_H
#define BOOTP_LOCAL_H

#include <stdint.h>
#include <netinet/in.h>

/* Structure BOOTP (RFC951/RFC1542) utilisée aussi par DHCP.
 * Taille fixe 236 octets avant les options DHCP.
 * On garde exactement les champs standards pour compatibilité pcap. */
struct bootp {
    uint8_t  bp_op;      /* 1=request, 2=reply */
    uint8_t  bp_htype;   /* type de hardware (1=Ethernet) */
    uint8_t  bp_hlen;    /* longueur adresse hardware (6 pour MAC) */
    uint8_t  bp_hops;    /* utilisé par relais BOOTP/DHCP */
    uint32_t bp_xid;     /* transaction ID */
    uint16_t bp_secs;    /* secondes depuis début acquisition */
    uint16_t bp_flags;   /* flags (bit broadcast, etc.) */
    struct in_addr bp_ciaddr; /* client IP (si déjà connue) */
    struct in_addr bp_yiaddr; /* "your" (adresse attribuée au client) */
    struct in_addr bp_siaddr; /* server IP */
    struct in_addr bp_giaddr; /* relay (gateway) IP */
    uint8_t  bp_chaddr[16];   /* adresse hardware client (MAC dans les 6 premiers octets) */
    char     bp_sname[64];    /* nom serveur optionnel */
    char     bp_file[128];    /* nom fichier boot optionnel */
    uint8_t  bp_vend[64];     /* zone options (legacy/BOOTP) */
};

/* Valeurs bp_op */
#define BOOTP_REQUEST 1
#define BOOTP_REPLY   2

/* Codes d'options DHCP (TLV) les plus utiles pour le TP */
#define DHCP_OPT_PAD        0   /* padding */
#define DHCP_OPT_REQ_IP     50  /* Requested IP Address */
#define DHCP_OPT_LEASE      51  /* IP Address Lease Time */
#define DHCP_OPT_MSG_TYPE   53  /* DHCP Message Type (DISCOVER/OFFER/REQUEST/ACK...) */
#define DHCP_OPT_SERVER_ID  54  /* DHCP Server Identifier */
#define DHCP_OPT_END        255 /* fin de la liste d'options */

#endif /* BOOTP_LOCAL_H */
