#include "packet_sniffing.h"
#include "packet_handler.h"
#include <pcap.h>

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