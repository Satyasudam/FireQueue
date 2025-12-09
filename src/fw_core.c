#include <string.h>
#include <arpa/inet.h>
#include "../include/fw_core.h"

rule_t *get_rule_table(int *count); // from rules.c

// Compare IP address with rule using prefix length
static int ip_match(const parsed_packet_t *pkt, const rule_t *r) {
    if (r->family == IP_FAMILY_ANY)
        return 1;

    if (r->family == IP_FAMILY_IPV4 && pkt->ip_version != 4)
        return 0;

    if (r->family == IP_FAMILY_IPV6 && pkt->ip_version != 6)
        return 0;

    const uint8_t *pkt_src = pkt->src_ip;
    const uint8_t *pkt_dst = pkt->dst_ip;
    const uint8_t *rule_src = r->src_ip;
    const uint8_t *rule_dst = r->dst_ip;

    int bytes = (r->src_prefix / 8);
    int bits  = (r->src_prefix % 8);

    // src IP
    if (r->src_prefix > 0) {
        if (memcmp(pkt_src, rule_src, bytes) != 0) return 0;
        if (bits) {
            uint8_t mask = ~((1 << (8 - bits)) - 1);
            if ((pkt_src[bytes] & mask) != (rule_src[bytes] & mask)) return 0;
        }
    }

    // dst IP
    bytes = (r->dst_prefix / 8);
    bits  = (r->dst_prefix % 8);
    if (r->dst_prefix > 0) {
        if (memcmp(pkt_dst, rule_dst, bytes) != 0) return 0;
        if (bits) {
            uint8_t mask = ~((1 << (8 - bits)) - 1);
            if ((pkt_dst[bytes] & mask) != (rule_dst[bytes] & mask)) return 0;
        }
    }

    return 1;
}

action_t firewall_decide(const parsed_packet_t *pkt, int *match_index) {
    int count;
    rule_t *rules = get_rule_table(&count);

    if (match_index) *match_index = -1;

    for (int i = 0; i < count; i++) {
        rule_t *r = &rules[i];

        if (!r->enabled) continue;

        // Protocol match
        if (r->proto != PROTO_ANY && r->proto != pkt->protocol)
            continue;

        // IP family + CIDR match
        if (!ip_match(pkt, r))
            continue;

        // Ports
        if (r->src_port != 0 && r->src_port != pkt->src_port)
            continue;

        if (r->dst_port != 0 && r->dst_port != pkt->dst_port)
            continue;

        if (match_index) *match_index = i;
        return r->action; // first match wins
    }

    if (match_index) *match_index = -1;
    return DEFAULT_POLICY;
}

