#include <stdio.h>
#include<fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/rules.h"

static rule_t rule_table[MAX_RULES];
static int rule_count = 0;

void init_rule_system() {
    rule_count = 0;
}

int add_rule(rule_t rule) {
    if(rule_count >= MAX_RULES) return -1;
    rule_table[rule_count] = rule;
    return rule_count++;
}

void list_rules() {
    printf("\n-- Rule List (%d rules) --\n", rule_count);
    for(int i = 0; i < rule_count; i++) {
        print_rule(&rule_table[i], i);
    }
}

void print_rule(rule_t *rule, int index) {
    char src_ip[32], dst_ip[32];
    inet_ntop(AF_INET, &rule->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &rule->dst_ip, dst_ip, sizeof(dst_ip));

    printf("[%d] %s | proto=%d | src=%s:%d → dst=%s:%d | %s\n",
        index,
        rule->enabled ? "ENABLED " : "DISABLED",
        rule->proto,
        src_ip, ntohs(rule->src_port),
        dst_ip, ntohs(rule->dst_port),
        rule->action == ACTION_ALLOW ? "ALLOW" : "DROP");
}

int delete_rule(int index) {
    if(index < 0 || index >= rule_count) return -1;
    for(int i = index; i < rule_count - 1; i++) {
        rule_table[i] = rule_table[i + 1];
    }
    rule_count--;
    return 0;
}

void enable_rule(int index, bool enable) {
    if(index < 0 || index >= rule_count) return;
    rule_table[index].enabled = enable;
}

// Save rules to file
int save_rules_to_file(const char *filename) {
    FILE *f = fopen(filename, "w");
    if(!f) { printf("error happended");return -1;}
    fwrite(&rule_count, sizeof(int), 1, f);
    fwrite(rule_table, sizeof(rule_t), rule_count, f);
    printf("The added rules are saved to the file -- %s\n",filename);
    fclose(f);
    return 0;
}

// Load rules from file
int load_rules_from_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if(!f) return -1;
    fread(&rule_count, sizeof(int), 1, f);
    fread(rule_table, sizeof(rule_t), rule_count, f);
    fclose(f);
    return 0;
}

rule_t* get_rule_table(int *count) {
    *count = rule_count;
    return rule_table;
}
