#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/logger.h"

static FILE *log_file = NULL;

void init_logger() {
    log_file = fopen(LOG_FILE_PATH, "a");
    if (!log_file) {
        perror("Logger init failed");
    }
}

static void ip_to_str(const parsed_packet_t *pkt, const uint8_t *ip, char *buf, size_t buflen) {
    if (pkt->ip_version == 4) {
        inet_ntop(AF_INET, ip, buf, buflen);
    } else if (pkt->ip_version == 6) {
        inet_ntop(AF_INET6, ip, buf, buflen);
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

void log_packet_decision(const parsed_packet_t *pkt, action_t decision, int rule_index) {
    if (!log_file || !pkt) return;

    char sip[64], dip[64];
    ip_to_str(pkt, pkt->src_ip, sip, sizeof(sip));
    ip_to_str(pkt, pkt->dst_ip, dip, sizeof(dip));

    fprintf(log_file,
            "v%d %s → %s | proto=%d | %s (rule %d)\n",
            pkt->ip_version,
            sip, dip,
            pkt->protocol,
            decision == ACTION_DROP ? "DROP" : "ALLOW",
            rule_index);
    fflush(log_file);
}

