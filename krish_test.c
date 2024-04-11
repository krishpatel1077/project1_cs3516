#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h> 
#include <net/ethernet.h> 
#include <netinet/if_ether.h>
#include <netinet/ip.h> //iphdr
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "/usr/include/netinet/tcp.h"
#include "/usr/include/netinet/udp.h"
#include "/usr/include/netinet/if_ether.h"

/*OUR STRUCTURE IS ADDRESSMAP: A general structure with two arrays
to hold any kind of network address and the # of occurrences for each*/
struct AddressMap {
    char** addresses; // Pointer to an array of addresses
    int16_t* occurrences;   // Pointer to an array of occurrence #s
    int size;
};

struct AddressMap *initAddressMap() {
    struct AddressMap *map = malloc(sizeof(struct AddressMap));
    if (!map) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    map->addresses = NULL;
    map->occurrences = NULL;
    map->size = 0;

    return map;
}

// Function to add an address to the AddressMap
void addAddress(struct AddressMap *a_map, char *address) {
    int isAdded = 0;

    // Allocate memory for a new address
    char *newAddress = strdup(address);
    if (!newAddress) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    //if new address has already been stored, add 1 to its occurrence 
    for(int i = 0; i < a_map->size; i++) {
        if(strcmp(a_map->addresses[i], newAddress) == 0) {
            a_map->occurrences[i]++;
            isAdded = 1;
        }
    }

    //if new address hasn't already been stored,
    if(isAdded == 0) { 
        //allocate the memory for the addresses so it can store the values
        a_map->addresses = realloc(a_map->addresses, (a_map->size + 1) * sizeof(char *));
        if (!a_map->addresses) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        //add on the new address
        a_map->addresses[a_map->size] = newAddress;

        //allocate the memory for the occurrences so it can store the values
        a_map->occurrences = realloc(a_map->occurrences, (a_map->size + 1) * sizeof(int16_t));
        if (!a_map->occurrences) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        //store the new occurrence
        a_map->occurrences[a_map->size] = 1;

        a_map->size++; // Increment the size of the map
    }
}

// Function to print the addresses stored in the AddressMap
void printAddresses(struct AddressMap *a_map) {
    printf("Addresses\n");
    for (int i = 0; i < a_map->size; i++) {
        printf("%s ", a_map->addresses[i]);
        printf("occurrences: %d\n", a_map->occurrences[i]);
    }
    printf("\n");
}

// Function to print the UDP ports stored in the AddressMap
void printUDPPorts(struct AddressMap *a_map) {
    printf("Ports:\n");
    for (int i = 0; i < a_map->size; i++) {
        printf("%s ", a_map->addresses[i]);
        printf("occurrences: %d\n", a_map->occurrences[i]);
    }
    printf("\n");
}

//this structure will hold all of the information needed to print statistics 
struct packetStats {
    int count; 
    int totalLen; 

    time_t local_tv_sec_start;
    time_t local_tv_usec_start;

    time_t local_tv_sec_end;
    time_t local_tv_usec_end;

    int minPacketSize; 
    int maxPacketSize; 

    struct AddressMap *ETH_src_map; 
    struct AddressMap *ETH_dst_map; 
    struct AddressMap *IP_src_map; 
    struct AddressMap *IP_dst_map; 
    struct AddressMap *UDP_src_map; 
    struct AddressMap *UDP_dst_map; 

    struct AddressMap *ARP_sender_map; // Map to store ARP sender MAC addresses
    struct AddressMap *ARP_recipient_map; // Map to store ARP recipient MAC addresses

    struct AddressMap *ARP_ip_sender_map;
    struct AddressMap *ARP_ip_recipient_map;

    int isARP;
    int isUDP;
    int isIP;
};

void getAddIpAddr(struct packetStats* packetStats, const u_char *packet) {
    packetStats->isIP = 1;
    struct iphdr *iph; 
    struct in_addr *ip_src; 
    struct in_addr *ip_dst;

    //get ip header
    iph = (struct iphdr *)(packet + 14);

    char src_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dest_addr, INET_ADDRSTRLEN);

    //add ip addresses, if it is already in the data 
    //structure, increase occurrence #

    addAddress(packetStats->IP_src_map, src_addr); 
    addAddress(packetStats->IP_dst_map, dest_addr); 
}

void getAddUDP(struct packetStats* packetStats, const u_char *packet, struct iphdr *iph) {
    packetStats->isUDP = 1;
    struct udphdr *udph;
    u_short sport, dport;
    char sportString[16];
    char dportString[16];
    u_int ip_len;

    ip_len = ntohs(iph->tot_len); // Convert to host byte order
    udph = (struct udphdr *)(packet + 14 + (iph->ihl * 4)); // Adjust offset by IP header length
    sport = ntohs(udph->source);
    dport = ntohs(udph->dest);

    sprintf(sportString, "%hu", sport);
    sprintf(dportString, "%hu", dport);

    addAddress(packetStats->UDP_src_map, sportString);
    addAddress(packetStats->UDP_dst_map, dportString);
}

void getAddEther(struct packetStats* packetStats, const u_char *packet) {
    struct ether_header *eth_header;
    struct ether_addr *eth_src; 
    struct ether_addr *eth_dst;

    //get ethernet header 
    eth_header = (struct ether_header *) packet; 
    eth_src = (struct ether_addr *) eth_header->ether_shost;
    eth_dst = (struct ether_addr *) eth_header->ether_dhost;

    //add eth addresses, if it is already in the data 
    //structure, increase occurrence #

    addAddress(packetStats->ETH_src_map, ether_ntoa(eth_src)); 
    addAddress(packetStats->ETH_dst_map, ether_ntoa(eth_dst)); 
}

void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    
    //increase packet count by one and increase total length
    struct packetStats* packetStats = (struct packetStats*)user_data; 
    packetStats->count++; 
    packetStats->totalLen = packetStats->totalLen + pkthdr->len;


    ///print time of starting packet capture 
    // Set up time relevant variables
    struct tm ltime;
    char timestr[22];
    time_t local_tv_sec;
    
    // Time conversion
    local_tv_sec = pkthdr->ts.tv_sec;
    localtime_r(&local_tv_sec, &ltime);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", &ltime); // Update format string
    printf("%s.%06ld ", timestr, pkthdr->ts.tv_usec); // Include microseconds

    //duration
    if(pkthdr->ts.tv_usec - packetStats->local_tv_usec_start < 0) {
        //handle negative wrap around 
        printf("%ld.%06ld ", (local_tv_sec - packetStats->local_tv_sec_start) - 1,
                         (pkthdr->ts.tv_usec - packetStats->local_tv_usec_start + 1000000));
    }
    else {
        printf("%ld.%06ld ", (local_tv_sec - packetStats->local_tv_sec_start),
                         (pkthdr->ts.tv_usec - packetStats->local_tv_usec_start));
    }

    //length 
    printf("%d\n", pkthdr->len);

    //if first packet, find start date and time of packet capture 
    if(packetStats->count == 1) {
        packetStats->local_tv_sec_start = pkthdr->ts.tv_sec;
        packetStats->local_tv_usec_start = pkthdr->ts.tv_usec;
    }

    //check if we need to update min or max packet size 
    if (pkthdr->len > packetStats->maxPacketSize) {
        packetStats->maxPacketSize = pkthdr->len;
    }
    
    if (pkthdr->len < packetStats->minPacketSize) {
        packetStats->minPacketSize = pkthdr->len;
    }

    //now we find all of the needed headers + addresses

    //get ethernet addrs and add to packetStats 
    getAddEther(packetStats, packet);

    //get ether header for later use
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet; 

    //determine is ARP is used, ip ether type is x0806
    if(eth_header->ether_type == 1544) {
        //arp is used 
        packetStats->isARP = 1;
        struct ether_arp *arp;
        struct ether_addr *sha, *tha;
        struct in_addr *spa, *tpa;

        arp = (struct ether_arp *)(packet + 14);

        sha = (struct ether_addr *)arp->arp_sha;
        tha = (struct ether_addr *)arp->arp_tha; 

        spa = (struct in_addr *)arp->arp_spa;
        tpa = (struct in_addr *)arp->arp_tpa; 

        char spa_addr[INET_ADDRSTRLEN] = "No ip address";
        char tpa_addr[INET_ADDRSTRLEN] = "No ip address";

        inet_ntop(AF_INET, spa, spa_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, tpa, tpa_addr, INET_ADDRSTRLEN);

        printf("spa addr %s \n", spa_addr);
        printf("tpa addr %s \n", tpa_addr);

        // Add sender MAC address to ARP sender map
        addAddress(packetStats->ARP_sender_map, ether_ntoa(sha));

        // Add recipient MAC address to ARP recipient map
        addAddress(packetStats->ARP_recipient_map, ether_ntoa(tha));
        
        
    }

    //else, ipV4 used if val is 8
    else if(eth_header->ether_type == 8) {
        //do IP stuff --> get and add IP addrs to packetStats
        getAddIpAddr(packetStats, packet); 

        //get ip header for later use
        struct iphdr *iph; 
        iph = (struct iphdr *)(packet + 14);
        
        //get udp header if UDP is used --> protocol field is 17
        if(iph->protocol == 17) {
            //do UDP stuff --> get and add UDP ports to packetStats
            getAddUDP(packetStats, packet, iph); 
        }
    }

}

void printStats(const struct packetStats *packetStats) {
    //print eth addresses 
    printf("Ethernet Source ");
    printAddresses(packetStats->ETH_src_map);
    printf("Ethernet Destination ");
    printAddresses(packetStats->ETH_dst_map);

    if(packetStats->isIP == 1) {
        //print ip addresses 
        printf("IP Source ");
        printAddresses(packetStats->IP_src_map);
        printf("IP Destination ");
        printAddresses(packetStats->IP_dst_map);
    }

    if(packetStats->isARP == 1) {
        //print ARP machines
        printf("ARP Sender ");
        printAddresses(packetStats->ARP_sender_map);
        printAddresses(packetStats->ARP_ip_sender_map);
        printf("ARP Recipient ");
        printAddresses(packetStats->ARP_recipient_map);
        printAddresses(packetStats->ARP_ip_recipient_map);
    }

    if(packetStats->isUDP == 1) {
        //print UDP ports 
        printf("UDP Source ");
        printUDPPorts(packetStats->UDP_src_map);
        printf("UDP Destination ");
        printUDPPorts(packetStats->UDP_dst_map);
    }

   ///print total number of packets 
    printf("Total packets processed: %d\n", packetStats->count); // Print the total number of packets
    
   ///print average packet length  
    int packet_len_avg = packetStats->totalLen/packetStats->count;
    printf("Average packet length: %d\n", packet_len_avg);

    ///print min packet length 
    printf("Minimum packet length: %d\n", packetStats->minPacketSize);

    //print max packet length 
    printf("Maximum packet length: %d\n", packetStats->maxPacketSize);

}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fname = "project2-arp-storm.pcap";
    pcap_t *pcap;

    //set up packetStats struct
    struct packetStats packetStats; 
    packetStats.count = 0;
    packetStats.totalLen = 0;
    packetStats.maxPacketSize = 0;
    packetStats.minPacketSize = 999;
    packetStats.ETH_dst_map = initAddressMap(); 
    packetStats.ETH_src_map = initAddressMap(); 
    packetStats.IP_dst_map = initAddressMap(); 
    packetStats.IP_src_map = initAddressMap(); 
    packetStats.UDP_dst_map = initAddressMap(); 
    packetStats.UDP_src_map = initAddressMap(); 
    packetStats.ARP_sender_map = initAddressMap(); 
    packetStats.ARP_recipient_map = initAddressMap(); 
    packetStats.isARP = 0;
    packetStats.isUDP = 0;
    packetStats.isIP = 0;

    // Open the input file
    pcap = pcap_open_offline(fname, errbuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "Error opening file: %s\n", errbuf);
        return 1;
    }

    int datalink = pcap_datalink(pcap);
    if (datalink == DLT_EN10MB) {
        printf("Data is from 10MB Ethernet!\n");
        // Start processing packets using pcap_loop
        int ret = pcap_loop(pcap, -1, my_packet_handler, (u_char*)&packetStats);
        if (ret == -1) {
            fprintf(stderr, "Error occurred during pcap_loop: %s\n", pcap_geterr(pcap));
        }
    } else {
        printf("ERROR! DATA NOT FROM ETHERNET\n");
    }
    
    printStats(&packetStats);

    pcap_close(pcap);
    return 0;
}
