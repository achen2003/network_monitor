#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

typedef struct ip *ip_header;


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Pointer to the Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Network hiearchy:
    // 

    // Print Ethernet information
    printf("Packet Length: %d\n", header->len);
    printf("Packet Type: %d\n", ntohs(eth_header->ether_type));
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Check if the packet is an IP packet (IPv4)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("=======================");
        
        // Pointer to the IP header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Protocol: %d\n", ip_header->ip_p);

        // Handle TCP and UDP protocols
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("TCP Source Port: %d\n", ntohs(tcp_header->source));
            printf("TCP Destination Port: %d\n", ntohs(tcp_header->dest));
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("UDP Source Port: %d\n", ntohs(udp_header->source));
            printf("UDP Destination Port: %d\n", ntohs(udp_header->dest));
        }
    }

    printf("\n");
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all devices available
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Select the first available device
    device = alldevs;

    // Open the device for packet capturing
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }

    // Capture packets (use 0 for inf loop)
    pcap_loop(handle, 0, packet_handler, NULL);

    // Clean up
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    
    return 0;
}
