#ifndef BOOTP_LOCAL_H
#define BOOTP_LOCAL_H

#include <stdint.h>
#include <netinet/in.h>

/* BOOTP/DHCP header */
struct bootp {
    uint8_t  bp_op;
    uint8_t  bp_htype;
    uint8_t  bp_hlen;
    uint8_t  bp_hops;
    uint32_t bp_xid;
    uint16_t bp_secs;
    uint16_t bp_flags;
    struct in_addr bp_ciaddr;
    struct in_addr bp_yiaddr;
    struct in_addr bp_siaddr;
    struct in_addr bp_giaddr;
    uint8_t  bp_chaddr[16];
    char     bp_sname[64];
    char     bp_file[128];
    /* vendor/DHCP options area (DHCP magic cookie usually starts here) */
    uint8_t  bp_vend[64];
};

#define BOOTP_REQUEST 1
#define BOOTP_REPLY   2

/* DHCP options we care about */
#define DHCP_OPT_PAD        0
#define DHCP_OPT_REQ_IP     50
#define DHCP_OPT_LEASE      51
#define DHCP_OPT_MSG_TYPE   53
#define DHCP_OPT_SERVER_ID  54
#define DHCP_OPT_END        255

#endif
