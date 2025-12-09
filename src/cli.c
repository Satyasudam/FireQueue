#include <stdio.h>
#include <arpa/inet.h>
#include "../include/cli.h"
#include "../include/rules.h"
#include "../include/config.h"

static void add_rule_prompt() {
    rule_t r = {0};
    r.enabled = true;

    printf("Action (0=ALLOW,1=DROP): ");
    int action; scanf("%d", &action);
    r.action = action;

    printf("Protocol (0=ANY,1=ICMP,6=TCP,17=UDP): ");
    scanf("%d", &r.proto);

    char ip[32];
    printf("Source IP (0 for any): ");
    scanf("%s", ip);
    inet_pton(AF_INET, ip, &r.src_ip);

    printf("Destination IP (0 for any): ");
    scanf("%s", ip);
    inet_pton(AF_INET, ip, &r.dst_ip);

    printf("Source port (0 for any): ");
    scanf("%hu", &r.src_port); r.src_port = htons(r.src_port);

    printf("Destination port (0 for any): ");
    scanf("%hu", &r.dst_port); r.dst_port = htons(r.dst_port);

    int id = add_rule(r);
    printf("\nAdded rule index %d\n", id);
}

void show_menu() {
    printf("\n===== FIREWALL MENU =====\n");
    printf("1. Add Rule\n");
    printf("2. List Rules\n");
    printf("3. Delete Rule\n");
    printf("4. Enable/Disable Rule\n");
    printf("5. Save Rules\n");
    printf("6. Load Rules\n");
    printf("7. Start Simulation\n");
    printf("0. Exit\n");
}

void menu_loop() {
    int choice;

    while(1) {
        show_menu();
        printf("Enter: ");
        scanf("%d", &choice);

        if(choice == 0) break;
        else if(choice == 1) add_rule_prompt();
        else if(choice == 2) list_rules();
        else if(choice == 3) {
            int x; printf("Index: "); scanf("%d",&x);
            delete_rule(x);
        }
        else if(choice == 4) {
            int x; printf("Index: "); scanf("%d",&x);
            int e; printf("1=enable 0=disable: "); scanf("%d",&e);
            enable_rule(x, e);
        }
        else if(choice == 5) save_rules_to_file(RULE_FILE_PATH);
        else if(choice == 6) load_rules_from_file(RULE_FILE_PATH);
        else if(choice == 7) break; // exit to main for simulation
        else{break;}
    }
}
