#include <stdio.h>
#include <pcap/pcap.h>
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/ether.h"
#include "/usr/include/netinet/if_ether.h"
//similar to above
#include "/usr/include/net/ethernet.h"
#include "/usr/include/netinet/tcp.h"
#include "/usr/include/netinet/udp.h"
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*OUR STRUCTURE IS ADDRESSMAP: A general structure with two char arrays
to hold any kind of network address for sender and receiver*/
struct AddressMap {
    char** sourceAddresses; // Pointer to an array of source addresses
    char** destAddresses;   // Pointer to an array of destination addresses
    int size;
};

struct AddressMap *initAddressMap() {
    struct AddressMap *map = malloc(sizeof(struct AddressMap));
    if (!map) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    map->sourceAddresses = NULL;
    map->destAddresses = NULL;
    map->size = 0;

    return map;
}

// Function to add an address to the AddressMap
//Identifier: 0 --> source, 1 --> destination
void addAddress(struct AddressMap *a_map, char *address, int identifier) {
    // Allocate memory for a new address
    char *newAddress = strdup(address);
    if (!newAddress) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    // identifier = 0 --> source address
    if (identifier == 0) {
        //allocate the memory for the source Address so it can store the values
        a_map->sourceAddresses = realloc(a_map->sourceAddresses, (a_map->size + 1) * sizeof(char *));
        if (!a_map->sourceAddresses) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        //add on the new address
        a_map->sourceAddresses[a_map->size] = newAddress;
    } 
    //identigier = 1 --> desitination address
    else if (identifier == 1) {
        //allocate the memory for the dest address so it can store the values
        a_map->destAddresses = realloc(a_map->destAddresses, (a_map->size + 1) * sizeof(char *));
        if (!a_map->destAddresses) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        //store the new address
        a_map->destAddresses[a_map->size] = newAddress;
    } else {
        printf("ERROR: BAD IDENTIFIER!\n");
        free(newAddress); // Free memory allocated for the new address
        return;
    }
    a_map->size++; // Increment the size of the map
}

// Function to print the addresses stored in the AddressMap
void printAddresses(struct AddressMap *a_map) {
    printf("Source Addresses:\n");
    for (int i = 0; i < a_map->size; i++) {
        printf("%s\n", a_map->sourceAddresses[i]);
    }

    printf("\nDestination Addresses:\n");
    for (int i = 0; i < a_map->size; i++) {
        printf("%s\n", a_map->destAddresses[i]);
    }
}


int totalpackets = 0;
int totallen = 0;
void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Set up time relevant variables
    struct tm ltime;
    char timestr[22];
    time_t local_tv_sec;
    totalpackets++;
    totallen += pkthdr->len;
    
    // Time conversion + length
    local_tv_sec = pkthdr->ts.tv_sec;
    localtime_r(&local_tv_sec, &ltime);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", &ltime); // Update format string
    printf("\n %s.%06ld len:%d \n", timestr, pkthdr->ts.tv_usec, pkthdr->len); // Include microseconds
   

    struct iphdr *iph; 
    struct ether_header *ethdr;
    struct ether_addr *ethr_src;
    struct ether_addr *ethr_dest;
    struct udphdr *udph;
    u_short sport, dport;
    u_int ip_len;
    int udp_len;

    //get ethernet header + destination and source address
    ethdr = (struct ether_header *)(packet);
    ethr_src = (struct ether_addr *)ethdr->ether_shost;
    ethr_dest = (struct ether_addr *)ethdr->ether_dhost;
    printf("src addr of eth header %s\n", ether_ntoa(ethr_src));
    
    //IP addresses
    iph = (struct iphdr *)(packet + 14);
    char src_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dest_addr, INET_ADDRSTRLEN);
    printf("Src IP: %s, Dst IP: %s\n", src_addr, dest_addr);

    //UDP action
    ip_len = iph->tot_len;
    udph = (struct udphdr *)(packet + 14 + ip_len);
    printf("UDP Src Port: %d, Dst Port: %d\n", ntohs(udph->uh_sport), ntohs(udph->uh_dport));
    


}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fname = "project2-dns.pcap";
    pcap_t *pcap;

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
        int ret = pcap_loop(pcap, -1, my_packet_handler, NULL);
        if (ret == -1) {
            fprintf(stderr, "Error occurred during pcap_loop: %s\n", pcap_geterr(pcap));
        }
    } else {
        printf("ERROR! DATA NOT FROM ETHERNET\n");
    }
    
    printf("\nTotal packets processed: %d\n", totalpackets); // Print the total number of packets
    int packet_len_avg = totallen/totalpackets;
    printf("AVERAGE PACKET LENGTH %d\n", packet_len_avg);
    pcap_close(pcap);
    return 0;
}
