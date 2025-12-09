#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H
//these are include guards 
#include <stdint.h>

// Unified representation for IPv4 + IPv6 packets
typedef struct {
    int      ip_version;         // 4 or 6
    uint8_t  protocol;           // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, etc.
    uint8_t  src_ip[16];         // IPv4: first 4 bytes used
    uint8_t  dst_ip[16];         // IPv4: first 4 bytes used
    uint16_t src_port;           // network byte order
    uint16_t dst_port;           // network byte order
} parsed_packet_t;

/**
 * Parse an L2 frame (Ethernet) into parsed_packet_t.
 * Used by SIMULATION MODE with libpcap (starts at Ethernet header).
 * Returns 0 on success, -1 on unsupported packet.
 */
int parse_l2_packet(const uint8_t *packet, parsed_packet_t *result);

/**
 * Parse an IP packet starting at the IP header (no Ethernet).
 * Used by ENFORCEMENT MODE via NFQUEUE.
 * Returns 0 on success, -1 on unsupported packet.
 */
int parse_ip_packet(const uint8_t *ip_packet, size_t len, parsed_packet_t *result);

#endif // PACKET_PARSER_H

