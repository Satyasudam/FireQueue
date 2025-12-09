#ifndef RULES_H
#define RULES_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

// Protocol constants
#define PROTO_ANY   0
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_ICMP  1
#define PROTO_ICMPV6 58

typedef enum {
    IP_FAMILY_ANY = 0,
    IP_FAMILY_IPV4 = 4,
    IP_FAMILY_IPV6 = 6
} ip_family_t;

typedef struct {
    bool       enabled;
    action_t   action;         // ALLOW or DROP
    int        proto;          // PROTO_ANY / TCP / UDP / ICMP / etc.
    ip_family_t family;        // ANY / IPv4 / IPv6

    // CIDR-style matching: address + prefix length
    uint8_t    src_ip[16];
    uint8_t    src_prefix;     // bits (0..128)
    uint8_t    dst_ip[16];
    uint8_t    dst_prefix;     // bits (0..128)

    uint16_t   src_port;       // 0 = any
    uint16_t   dst_port;       // 0 = any
} rule_t;

// Rule operations
void   init_rule_system();
int    add_rule(rule_t rule);
void   list_rules();
int    delete_rule(int index);
void   enable_rule(int index, bool enable);
int    load_rules_from_file(const char *filename);
int    save_rules_to_file(const char *filename);
void   print_rule(rule_t *rule, int index);

// Internal access for FW core
rule_t *get_rule_table(int *count);

#endif // RULES_H

