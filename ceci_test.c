//There will be code here
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h> 
#include <netinet/if_ether.h>
#include <netinet/ip.h> //iphdr


int totalpackets = 0;
int totallen = 0;

void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    totalpackets++;
    totallen += pkthdr->len;
    printf("Received a packet of length %d\n", pkthdr->len);
    printf("Time Stamp of the packet is %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    
    struct iphdr *iph; 
    struct ether_header *eth_header;
    struct ether_addr *eth_src; 

    //get ethernet header 
    eth_header = (struct ether_header *) packet; 
    eth_src = (struct ether_addr *) eth_header->ether_dhost;

    printf("src addr of eth header %s\n", ether_ntoa(eth_src));
   //  printf("src addr of eth header %s\n", inet_ntop(4, eth_src, eth_src_addr, 4));

    //get ip header
    iph = (struct iphdr *)(packet + 14);
    printf("destination addr of ip header %d\n", (iph->daddr));

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
