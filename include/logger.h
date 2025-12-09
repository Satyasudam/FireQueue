#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include "config.h"
#include "packet_parser.h"

// Logging functions
void init_logger();
void log_packet_decision(const parsed_packet_t *pkt, action_t decision, int rule_index);

#endif // LOGGER_H
