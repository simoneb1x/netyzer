#include "packet_handler.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <net/ethernet.h>

// Callback function that is called whenever a packet is captured:
// u_char *args: optional data pointer that can be passed to pcap_loop() when the packet sniffing is initializated;
// const struct pcap_pkthdr *header: a pointer to the pcap_pkthdr structure that contains captured packet's header informations,
// such as its length and the capture timestamp;
// const u_char *packet: byte array's pointer that represent the captured packet contents
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // header conversion in a time_t structure in order to
    // manipulate datetime and hours
    struct tm *timeinfo;
    char buffer[80];
    time_t rawtime = header->ts.tv_sec;
    timeinfo = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    // we get the ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    printf("\n*******************************\n");
    printf("Packet captured at: %s\n", buffer);

    // pointer to the first packet byte
    const u_char *payload = packet + sizeof(struct ether_header);

    // packet's data dimensions
    int payload_size = header->len - sizeof(struct ether_header);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        // get the ip header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            // get the tcp header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            // get the udp header
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
        }
        else if (ip_header->ip_p == IPPROTO_ICMP)
        {
            // get the icmp header
            struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
            printf("ICMP Type: %d\n", icmp_header->icmp_type);
            printf("ICMP Code: %d\n", icmp_header->icmp_code);
        }
    }

    // packet data visualization
    printf("Packet data:\n");
    for (int i = 0; i < payload_size; i++)
    {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    };
    

    // divider
    printf("\n*******************************\n");
}
