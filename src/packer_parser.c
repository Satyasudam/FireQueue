#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "../include/packet_parser.h"

static void parse_ports(uint8_t protocol, const void *l4, uint16_t *sport, uint16_t *dport) {
    *sport = 0;
    *dport = 0;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        *sport = tcp->source;
        *dport = tcp->dest;
    } else if (protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)l4;
        *sport = udp->source;
        *dport = udp->dest;
    }
}

// L2 parse (Ethernet) → used in simulation mode (pcap)
int parse_l2_packet(const uint8_t *packet, parsed_packet_t *res) {
    memset(res, 0, sizeof(*res));
    const struct ether_header *eth = (const struct ether_header *)packet;
    uint16_t eth_type = ntohs(eth->ether_type);

    const uint8_t *payload = packet + sizeof(struct ether_header);

    if (eth_type == ETHERTYPE_IP) {
        // IPv4
        const struct ip *ip4 = (const struct ip *)payload;
        int iphdr_len = ip4->ip_hl * 4;

        res->ip_version = 4;
        res->protocol   = ip4->ip_p;
        // store IPv4 in first 4 bytes of src_ip/dst_ip
        memcpy(res->src_ip, &ip4->ip_src, 4);
        memcpy(res->dst_ip, &ip4->ip_dst, 4);

        const uint8_t *l4 = payload + iphdr_len;
        parse_ports(res->protocol, l4, &res->src_port, &res->dst_port);
        return 0;
    } else if (eth_type == ETHERTYPE_IPV6) {
        // IPv6
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)payload;

        res->ip_version = 6;
        res->protocol   = ip6->ip6_nxt;
        memcpy(res->src_ip, &ip6->ip6_src, 16);
        memcpy(res->dst_ip, &ip6->ip6_dst, 16);

        const uint8_t *l4 = payload + sizeof(struct ip6_hdr);
        parse_ports(res->protocol, l4, &res->src_port, &res->dst_port);
        return 0;
    }

    return -1; // Unsupported
}

// L3 parse (IP-only) → used in NFQUEUE (enforcement)
int parse_ip_packet(const uint8_t *ip_packet, size_t len, parsed_packet_t *res) {
    memset(res, 0, sizeof(*res));

    if (len < 1) return -1;

    uint8_t v = (ip_packet[0] >> 4) & 0xF;

    if (v == 4) {
        if (len < sizeof(struct ip)) return -1;
        const struct ip *ip4 = (const struct ip *)ip_packet;
        int iphdr_len = ip4->ip_hl * 4;
        if (len < (size_t)iphdr_len) return -1;

        res->ip_version = 4;
        res->protocol   = ip4->ip_p;
        memcpy(res->src_ip, &ip4->ip_src, 4);
        memcpy(res->dst_ip, &ip4->ip_dst, 4);

        const uint8_t *l4 = ip_packet + iphdr_len;
        if (len > (size_t)iphdr_len)
            parse_ports(res->protocol, l4, &res->src_port, &res->dst_port);

        return 0;
    } else if (v == 6) {
        if (len < sizeof(struct ip6_hdr)) return -1;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_packet;

        res->ip_version = 6;
        res->protocol   = ip6->ip6_nxt;
        memcpy(res->src_ip, &ip6->ip6_src, 16);
        memcpy(res->dst_ip, &ip6->ip6_dst, 16);

        const uint8_t *l4 = ip_packet + sizeof(struct ip6_hdr);
        if (len > sizeof(struct ip6_hdr))
            parse_ports(res->protocol, l4, &res->src_port, &res->dst_port);

        return 0;
    }

    return -1;
}

