//There will be code here
#include <stdio.h>
#include <pcap/pcap.h>

int totalpackets = 0;
int totallen = 0;
void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    totalpackets++;
    totallen += pkthdr->len;
    printf("Received a packet of length %d\n", pkthdr->len);
    printf("Time Stamp of the packet is %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    
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
