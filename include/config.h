#ifndef CONFIG_H
#define CONFIG_H

// Default firewall settings
#define MAX_RULES          100
#define LOG_FILE_PATH      "../data/firewall.log"
#define RULE_FILE_PATH     "/home/asus/Desktop/ipv6_integ/data/rules.conf"

// Default policy if no rule matches (ALLOW / DROP)
#define DEFAULT_POLICY     ACTION_ALLOW

// Menu options
#define TRUE  1
#define FALSE 0

// Actions
typedef enum {
    ACTION_ALLOW = 0,
    ACTION_DROP  = 1
} action_t;

#endif // CONFIG_H
