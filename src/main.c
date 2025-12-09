#include <stdio.h>
#include <pcap.h>
#include "../include/config.h"
#include "../include/packet_parser.h"
#include "../include/fw_core.h"
#include "../include/logger.h"
#include "../include/cli.h"
#include "../include/stats.h"
#include "../include/nfqueue_handler.h"

static void sim_packet_handler(u_char *args,
                               const struct pcap_pkthdr *header,
                               const u_char *packet)
{
    (void)args;
    (void)header;

    parsed_packet_t pkt;
    if (parse_l2_packet(packet, &pkt) != 0)
        return;

    int match_index = -1;
    action_t verdict = firewall_decide(&pkt, &match_index);

    if (verdict == ACTION_DROP) stats_inc_dropped();
    else stats_inc_allowed();

    log_packet_decision(&pkt, verdict, match_index);
    stats_print();
}

int main() {
    init_rule_system();
    init_logger();

    // Configure rules first
    lab:menu_loop();
  //came when simulation is choosen
    int mode;
    printf("\nSelect mode:\n1. Simulation (pcap)\n2. Enforcement (NFQUEUE)\n3. Main menu\n0. Exit\nChoice: ");
    scanf("%d", &mode);

    if (mode == 1) {
        char errbuf[PCAP_ERRBUF_SIZE];
        // TODO: ask user for interface
        const char *iface = "wlan0";
        //scanf("%s",iface);
        pcap_t *handle = pcap_open_live(iface, 65535, 1, 10, errbuf);
        if (!handle) {
            printf("PCAP error: %s\n", errbuf);
            return 1;
        }

        printf("[*] Starting Simulation Mode on %s...\n", iface);
        pcap_loop(handle, 0, sim_packet_handler, NULL);
        pcap_close(handle);
    } else if (mode == 2) {
        int qnum = 0; //choosing a particular nfqueue queue number
        printf("[*] Starting Enforcement Mode on NFQUEUE %d...\n", qnum);
        start_nfqueue_loop(qnum);}
        else if(mode==3){goto lab;
        }
        else if(mode ==0){
        printf("Exiting from the program\n*************");
         return 0;
        }
        else {
        printf("Invalid mode.\n");
    }

    return 0;
}

