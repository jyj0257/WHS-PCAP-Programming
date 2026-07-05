#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    u_char *payload = (u_char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
    int i;

    (void)args;
    (void)header;

    if (ntohs(eth->ether_type) != 0x0800 || ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    printf("\n================ Packet ================\n");
    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));
    printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %u\n", ntohs(tcp->tcp_dport));

    if (ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80) {
        printf("HTTP Message:\n");
        for (i = 0; i < payload_len; i++) {
            putchar(isprint(payload[i]) || payload[i] == '\r' || payload[i] == '\n' ? payload[i] : '.');
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;
    const char *dev = "enp0s3";

    if (argc >= 2) {
        dev = argv[1];
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "pcap_compile");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "pcap_setfilter");
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
