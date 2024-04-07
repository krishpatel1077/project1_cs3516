//There will be code here
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h> 
#include <netinet/if_ether.h>
#include <netinet/ip.h> //iphdr
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "/usr/include/netinet/tcp.h"
#include "/usr/include/netinet/udp.h"

/*OUR STRUCTURE IS ADDRESSMAP: A general structure with two arrays
to hold any kind of network address and the # of occurences for each*/
struct AddressMap {
    char** addresses; // Pointer to an array of addresses
    int16_t* occurences;   // Pointer to an array of occurence #s
    int size;
};

struct AddressMap *initAddressMap() {
    struct AddressMap *map = malloc(sizeof(struct AddressMap));
    if (!map) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    map->addresses = NULL;
    map->occurences = NULL;
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

    //if new address has already been stored, add 1 to its occurence 
    for(int i = 0; i < a_map->size; i++) {
        if(strcmp(a_map->addresses[i], newAddress) == 0) {
            a_map->occurences[i]++;
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

        //allocate the memory for the occurences so it can store the values
        a_map->occurences = realloc(a_map->occurences, (a_map->size + 1) * sizeof(char *));
        if (!a_map->occurences) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        //store the new occurence
        a_map->occurences[a_map->size] = 1;

        a_map->size++; // Increment the size of the map
    }
}

// Function to print the addresses stored in the AddressMap
void printAddresses(struct AddressMap *a_map) {
    printf("Addresses\n");
    for (int i = 0; i < a_map->size; i++) {
        printf("%s ", a_map->addresses[i]);
        printf("occurences: %d\n", a_map->occurences[i]);
    }
}

//this structure will hold all of the information needed to print statistics 
struct packetStats{
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


};

void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    //increase packet count by one and increase total length
    struct packetStats* packetStats = (struct packetStats*)user_data; 
    packetStats->count++; 
    packetStats->totalLen = packetStats->totalLen + pkthdr->len;
   // printf("Received a packet of length %d\n", pkthdr->len);

    //if first packet, find start date and time of packet capture 
    if(packetStats->count == 1) {
        packetStats->local_tv_sec_start = pkthdr->ts.tv_sec;
        packetStats->local_tv_usec_start = pkthdr->ts.tv_usec;
    }

    //update "last packet" time stats -- will be overwritten until 
    //actual last packet comes
    packetStats->local_tv_sec_end = pkthdr->ts.tv_sec;
    packetStats->local_tv_usec_end = pkthdr->ts.tv_usec;

    //check if we need to update min or max packet size 
    if (pkthdr->len > packetStats->maxPacketSize) {
        packetStats->maxPacketSize = pkthdr->len;
    }
    
    if (pkthdr->len < packetStats->minPacketSize) {
        packetStats->minPacketSize = pkthdr->len;
    }

    //now we find all of the needed headers + addresses 
    struct ether_header *eth_header;
    struct ether_addr *eth_src; 
    struct ether_addr *eth_dst;

    //get ethernet header 
    eth_header = (struct ether_header *) packet; 
    eth_src = (struct ether_addr *) eth_header->ether_shost;
    eth_dst = (struct ether_addr *) eth_header->ether_dhost;

    //add eth addresses, if it is already in the data 
    //structure, increase occurence #

    //printf("src addr of eth header %s\n", ether_ntoa(eth_src));
    addAddress(packetStats->ETH_src_map, ether_ntoa(eth_src)); 
    addAddress(packetStats->ETH_dst_map, ether_ntoa(eth_dst)); 

    struct iphdr *iph; 
    struct in_addr *ip_src; 
    struct in_addr *ip_dst;
    struct in_addr destination; 

    //get ip header
    iph = (struct iphdr *)(packet + 14);

    char src_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dest_addr, INET_ADDRSTRLEN);

    //printf("Src IP: %s, Dst IP: %s\n", src_addr, dest_addr);

    //add ip addresses, if it is already in the data 
    //structure, increase occurence #

    addAddress(packetStats->IP_src_map, src_addr); 
    addAddress(packetStats->IP_dst_map, dest_addr); 


    //get udp header -- CHECK IF UDP IS USED FIRST
    struct udphdr *udph;
    u_short sport, dport;
    u_int ip_len;
    struct udpheader *uh;

    ip_len = iph->tot_len;
    udph = (struct udphdr *)(packet + 14 + ip_len);

    char udpsrc_addr[16];
    char udpdest_addr[16];
    inet_ntop(PF_INET, &(udph->uh_sport), udpsrc_addr, 16);
    inet_ntop(PF_INET, &(udph->uh_dport), udpdest_addr, 16);
    printf("Src UDP: %s, Dst UDP: %s\n", udpsrc_addr, udpdest_addr);

}

void printStats(const struct packetStats *packetStats) {
    ///print time of starting packet capture 

    // Set up time relevant variables
    struct tm ltime;
    char timestr[22];
    time_t local_tv_sec;
    
    // Time conversion
    local_tv_sec = packetStats->local_tv_sec_start;
    localtime_r(&local_tv_sec, &ltime);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", &ltime); // Update format string
    printf("Start date and time of packet capture: %s.%06ld\n", timestr, packetStats->local_tv_usec_start); // Include microseconds
   
   ///print duration
   int totalSecs = packetStats->local_tv_sec_end - packetStats->local_tv_sec_start;    
   int totalUSecs = packetStats->local_tv_usec_end - packetStats->local_tv_usec_start;    
   printf("Duration of packet capture: %d.0%d seconds\n", totalSecs, totalUSecs);

    //print eth addresses 
    printf("Ethernet Source ");
    printAddresses(packetStats->ETH_src_map);
    printf("Ethernet Destination ");
    printAddresses(packetStats->ETH_dst_map);

    //print ip addresses 
    printf("IP Source ");
    printAddresses(packetStats->IP_src_map);
    printf("IP Destination ");
    printAddresses(packetStats->IP_dst_map);


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
    const char *fname = "project2-dns.pcap";
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
