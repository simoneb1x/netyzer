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

int main(int argc, char *argv[]) {
    // variables
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;

    // finding the network interface to use
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    dev = alldevs;
    if (dev == NULL) {
        printf("No devices found.\n");
        return 1;
    }
    printf("Using device: %s\n", dev->name);

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        printf("Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
