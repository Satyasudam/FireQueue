#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <linux/netfilter.h>
#include<arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "../include/nfqueue_handler.h"
#include "../include/packet_parser.h"
#include "../include/fw_core.h"
#include "../include/logger.h"
#include "../include/stats.h"
#ifndef NF_ACCEPT
#define NF_ACCEPT 1
#endif
#ifndef NF_DROP
#define NF_DROP 0
#endif

// Callback for each packet from NFQUEUE
static int cb(struct nfq_q_handle *qh,
              struct nfgenmsg *nfmsg,
              struct nfq_data *nfa,
              void *data)
{
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;

    uint32_t id = ntohl(ph->packet_id);  //every kernel netlink messages contain and ID

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);
    if (len <= 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    parsed_packet_t pkt;
    if (parse_ip_packet(payload, (size_t)len, &pkt) != 0) {
        // Unknown/unsupported packet, just ACCEPT
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    int match_index = -1;
    action_t verdict = firewall_decide(&pkt, &match_index);

    if (verdict == ACTION_DROP) stats_inc_dropped();
    else stats_inc_allowed();

    log_packet_decision(&pkt, verdict, match_index);

    uint32_t nf_verdict = (verdict == ACTION_DROP) ? NF_DROP : NF_ACCEPT;
    return nfq_set_verdict(qh, id, nf_verdict, 0, NULL);
}

int start_nfqueue_loop(int queue_num) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));  //strictly aligns this buffer in 16byte boundary

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error: nfq_open() failed\n");
        return -1;
    }

    // Unbind existing handlers
    if (nfq_unbind_pf(h, AF_INET) < 0) {/* ignore */}
    if (nfq_unbind_pf(h, AF_INET6) < 0) {/* ignore */}

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_bind_pf(AF_INET)\n");
        nfq_close(h);
        return -1;
    }
    if (nfq_bind_pf(h, AF_INET6) < 0) {
        fprintf(stderr, "Warning: nfq_bind_pf(AF_INET6) failed (no IPv6?)\n");
    }

    qh = nfq_create_queue(h, queue_num, &cb, NULL);  //asigned the callback function i.e send the netlink message to the kernel along with the verdicts
    if (!qh) {
        fprintf(stderr, "Error: nfq_create_queue()\n");
        nfq_close(h);
        return -1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: nfq_set_mode()\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }

    fd = nfq_fd(h);

    printf("[*] NFQUEUE enforcement running on queue %d\n", queue_num);
    printf("    Use iptables/ip6tables to send packets to NFQUEUE.\n");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {  //receiving the netlink messages from the kernel
        nfq_handle_packet(h, buf, rv);  //the callback function is invoked on those netlink packets
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

