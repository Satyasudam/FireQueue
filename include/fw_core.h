#ifndef FW_CORE_H
#define FW_CORE_H

#include "./packet_parser.h"
#include "rules.h"
#include "logger.h"
#include "config.h"
// Evaluate packet vs rule table → return ALLOW/DROP
action_t firewall_decide(const parsed_packet_t *pkt,int *match_index);

#endif // FW_CORE_H
