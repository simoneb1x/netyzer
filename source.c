#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
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

    // visualization
    printf("Packet data:\n");
    for (int i = 0; i < payload_size; i++)
    {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    printf("\n");
}


// This function starts the packet sniffing and its handling. It takes
// pcap_t *handle as an argument, that is a pointer to the pcap_t structure that
// represent the sniffing channel
void packet_sniffing(pcap_t *handle)
{
    // this will contain the captured packets header
    struct pcap_pkthdr header;

    // this will point at an array of bytes that represent the captured packet contents
    const u_char *packet;

    // pcap_loop receives the packets and calls a callback function for each received packet
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        // packet elaboration
        packet_handler(NULL, &header, packet);
    }
}

int main(int argc, char *argv[])
{
    // variables
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    int stop_option = 0;

    int option_choice;

    printf("Welcome to Netyzer.\n");

    do 
    {
        printf("Please, select an option:\n");
        printf("1. Packet Sniffing\n");
        printf("2. Exit\n");

        scanf("%d", &option_choice);

        switch (option_choice)
        {
        case 1:
            // finding the network interface to use
            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                printf("Error finding devices: %s\n", errbuf);
                return 1;
            }

            dev = alldevs;
            if (dev == NULL)
            {
                printf("No devices found.\n");
                return 1;
            }
            printf("Using device: %s\n", dev->name);

            handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL)
            {
                printf("Error opening device: %s\n", errbuf);
                pcap_freealldevs(alldevs);
                return 1;
            }

            packet_sniffing(handle);
            break;
        case 2:
            printf("Exiting program...\n");
            exit(0);
            break;
        default:
            printf("Invalid option selected.\n");
            break;
        }
    } while (stop_option < 1);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
