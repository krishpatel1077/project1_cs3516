#include <stdio.h>
#include <pcap/pcap.h>
#include "/usr/include/netinet/ip.h"
#include "/usr/include/netinet/if_ether.h"
//similar to above
#include "/usr/include/net/ethernet.h"
#include "/usr/include/netinet/tcp.h"
#include "/usr/include/netinet/udp.h"
#include <time.h>
#include <stdint.h>

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
    printf("%s.%06ld len:%d \n", timestr, pkthdr->ts.tv_usec, pkthdr->len); // Include microseconds
   

    struct iphdr *iph; 
    struct ether_header *ethdr;
    struct ether_addr *ethr_src;
    struct ether_addr *ethr_dest;

    //get ethernet header + destination and source address
    ethdr = (struct ether_header *)(packet);
    ethr_src = (struct ether_addr *)ethdr->ether_shost;
    ethr_dest = (struct ether_addr *)ethdr->ether_dhost;
    
    //IP addresses
    iph = (struct iphdr *)(packet + 14);
    char src_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dest_addr, INET_ADDRSTRLEN);
    printf("Src IP: %s, Dst IP: %s\n", src_addr, dest_addr);
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
    
    printf("Total packets processed: %d\n", totalpackets); // Print the total number of packets
    int packet_len_avg = totallen/totalpackets;
    printf("AVERAGE PACKET LENGTH %d\n", packet_len_avg);
    pcap_close(pcap);
    return 0;
}
