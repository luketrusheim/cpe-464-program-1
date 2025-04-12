#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "checksum.h"

#define ETHERNET_HEADER_LEN 14
#define PSEUDO_HEADER_LEN 12

struct ethernet_header {   
    struct ether_addr dest_addr;
    struct ether_addr src_addr;
    uint16_t type;
} __attribute__((packed));

struct arp_header {   
    // first four fields are unused, only there for easy packing
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;
    uint16_t opcode;
    struct ether_addr sender_hardware_addr;
    struct in_addr sender_protocol_addr;
    struct ether_addr target_hardware_addr;
    struct in_addr target_protocol_addr;
} __attribute__((packed));

struct ip_header {   
    uint8_t version_ihl; // stored together
    uint8_t TOS;
    uint16_t total_length;
    uint32_t id_flags_fragOffset; // not used so I lumped together
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr src_addr;
    struct in_addr dest_addr;
} __attribute__((packed));

struct tcp_header {   
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t dataOffset_reserved; // stored together
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

struct pseudo_header {   
    struct in_addr src_addr;
    struct in_addr dest_addr;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t seg_len_network;
} __attribute__((packed));

struct icmp_header {  
    uint8_t type; // only need this attribute
} __attribute__((packed));

struct udp_header {  
    uint16_t src_port;
    uint16_t dest_port;
} __attribute__((packed));

void print_port_info(const char *type, uint16_t port_network_order) {
    uint16_t port = ntohs(port_network_order);
    printf("\t\t%s Port:  ", type);

    switch (port) {
        case 80: printf("HTTP\n"); break;
        case 23: printf("Telnet\n"); break;
        case 20: printf("FTP\n"); break;
        case 110: printf("POP3\n"); break;
        case 25: printf("SMTP\n"); break;
        case 53: printf("DNS\n"); break;
        default: printf("%d\n", port); break;
    }
}

void process_udp(const u_char *pkt_data, const uint16_t seg_len_host, struct pseudo_header my_pseudo_header) {
    const struct udp_header *header = (const struct udp_header *)pkt_data;

    printf("\n\tUDP Header\n");
    print_port_info("Source", header->src_port);
    print_port_info("Dest", header->dest_port);
}

void process_icmp(const u_char *pkt_data, const uint16_t seg_len_host, struct pseudo_header my_pseudo_header) {
    const struct icmp_header *header = (const struct icmp_header *)pkt_data;

    printf("\n\tICMP Header\n");

    printf("\t\tType: ");
    switch (header->type) {
        case 8: 
            printf("Request\n");
            break;
        case 0: 
            printf("Reply\n");
            break;
        default: 
            printf("%d\n", header->type);
            break;
    }
}

void process_tcp(const u_char *pkt_data, const uint16_t seg_len_host, struct pseudo_header my_pseudo_header) {
    const struct tcp_header *header = (const struct tcp_header *)pkt_data;

    printf("\n\tTCP Header\n");
    printf("\t\tSegment Length: %d\n", seg_len_host);
    print_port_info("Source", header->src_port);
    print_port_info("Dest", header->dest_port);
    printf("\t\tSequence Number: %u\n", ntohl(header->seq_num));
    printf("\t\tACK Number: %u\n", ntohl(header->ack_num));

    int data_offset_bytes = ((header->dataOffset_reserved & 0xF0) >> 4) * 4;
    printf("\t\tData Offset (bytes): %d\n", data_offset_bytes);

    printf("\t\tSYN Flag: ");
    header->flags & 0x02 ? printf("Yes\n") : printf("No\n"); // 0b00000010
    printf("\t\tRST Flag: ");
    header->flags & 0x04 ? printf("Yes\n") : printf("No\n"); // 0b00000100
    printf("\t\tFIN Flag: ");
    header->flags & 0x01 ? printf("Yes\n") : printf("No\n"); // 0b00000001
    printf("\t\tACK Flag: ");
    header->flags & 0x10 ? printf("Yes\n") : printf("No\n"); // 0b00010000

    printf("\t\tWindow Size: %d\n", ntohs(header->window));

    // dyanmically allocate space for pseudo_header + TCP segment for checksum func.
    u_char *segment_with_pseudo = (u_char *)malloc(PSEUDO_HEADER_LEN + seg_len_host);
    memcpy(segment_with_pseudo, &my_pseudo_header, PSEUDO_HEADER_LEN);
    memcpy(segment_with_pseudo + PSEUDO_HEADER_LEN, pkt_data, seg_len_host);
    // for (size_t i = 0; i < 44; i++) {
    //     printf("%02x ", segment_with_pseudo[i]);  // print byte as 2-digit hex
    //     if ((i + 1) % 16 == 0) printf("\n"); // optional: new line every 16 bytes
    // }
    // printf("\n");
    // printf("my_pseudo_header: %lu, seg_len_host: %d, %d\n", sizeof(my_pseudo_header), seg_len_host, 12 + seg_len_host);
    if (in_cksum((unsigned short *)(segment_with_pseudo), PSEUDO_HEADER_LEN + seg_len_host) == 0) {
        printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(header->checksum));
    } else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(header->checksum));

    free(segment_with_pseudo);
}

void process_ip(const u_char *pkt_data) {
    const struct ip_header *header = (const struct ip_header *)pkt_data;

    printf("\n\tIP Header\n");

    const uint16_t pdu_len = ntohs(header->total_length);
    printf("\t\tIP PDU Len: %d\n", pdu_len);

    int header_len_bytes = (header->version_ihl & 0x0F) * 4;
    printf("\t\tHeader Len (bytes): %d\n", header_len_bytes);

    printf("\t\tTTL: %d\n", header->TTL);

    printf("\t\tProtocol: ");
    void (*next_process)(const u_char *, const uint16_t, struct pseudo_header) = NULL; // func pointer
    switch (header->protocol) {
        case 0x06:
            printf("TCP\n");
            next_process = process_tcp;
            break;
        case 0x01:
            printf("ICMP\n");
            next_process = process_icmp;
            break;
        case 0x11:
            printf("UDP\n");
            next_process = process_udp;
            break;
        default:
            printf("Unknown\n");
    }

    if (in_cksum((unsigned short *)(pkt_data), header_len_bytes) == 0)
        printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(header->checksum));
    else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(header->checksum));
    
    printf("\t\tSender IP: %s\n", inet_ntoa(header->src_addr));
    printf("\t\tDest IP: %s\n", inet_ntoa(header->dest_addr));

    pkt_data += header_len_bytes;
    const uint16_t seg_len_host = pdu_len - header_len_bytes;
    const uint16_t seg_len_network = htons(seg_len_host);
    // printf("seg_len_host: %02x\n", seg_len_host);
    // printf("seg_len_network: %02x\n", seg_len_network);
    struct pseudo_header my_pseudo_header = {
        .src_addr = header->src_addr,
        .dest_addr = header->dest_addr,
        .protocol = header->protocol,
        .seg_len_network = seg_len_network,
        // purposely not intializing .zeros because they will be nulled out (set to zero)
    };
    if (next_process) {
        next_process(pkt_data, seg_len_host, my_pseudo_header);
    }
}

void process_arp(const u_char *pkt_data) {
    const struct arp_header *header = (const struct arp_header *)pkt_data;

    printf("\n\tARP header\n");
    ntohs(header->opcode) == 1 ? printf("\t\tOpcode: Request\n") : printf("\t\tOpcode: Reply\n");
    printf("\t\tSender MAC: %s\n", ether_ntoa(&(header->sender_hardware_addr)));
    printf("\t\tSender IP: %s\n", inet_ntoa(header->sender_protocol_addr));
    printf("\t\tTarget MAC: %s\n", ether_ntoa(&(header->target_hardware_addr)));
    printf("\t\tTarget IP: %s\n", inet_ntoa(header->target_protocol_addr));
}

void process_ethernet(const u_char *pkt_data) {
    const struct ethernet_header *header = (const struct ethernet_header *)pkt_data;
    pkt_data += ETHERNET_HEADER_LEN;

    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n", ether_ntoa(&(header->dest_addr)));
    printf("\t\tSource MAC: %s\n", ether_ntoa(&(header->src_addr)));
    printf("\t\tType: ");
    switch (ntohs(header->type)) {
        case ETHERTYPE_IP: 
            printf("IP\n");
            process_ip(pkt_data);
            break;
        case ETHERTYPE_ARP: 
            printf("ARP\n");
            process_arp(pkt_data);
            break;
    }
}

int process_packets(pcap_t *pcap_file) {
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int packet_count = 0;

    while (pcap_next_ex(pcap_file, &pkt_header, &pkt_data) >= 0) {
        printf("\nPacket number: %d  Packet Len: %d\n\n", ++packet_count, pkt_header->caplen);
        process_ethernet(pkt_data);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char input_filename[256];
    strncpy(input_filename, argv[1], sizeof(input_filename));
    input_filename[sizeof(input_filename) - 1] = '\0'; // null-terminate

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_file = pcap_open_offline(input_filename, errbuf);
    
    if (pcap_file == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
        return 1;
    }

    process_packets(pcap_file);

    pcap_close(pcap_file);
    return 0;
}
