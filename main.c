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
#include "packet_handler.h"
#include "packet_sniffing.h"

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
