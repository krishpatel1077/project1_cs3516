#include <stdio.h>
#include <pcap/pcap.h>

void my_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Received a packet of length %d\n", pkthdr->len);
}

int main() {
    char ebuf[PCAP_ERRBUF_SIZE];
    const char *fname = "project2-dns.pcap";
    pcap_t *pcap;

    // Open the input file
    pcap = pcap_open_offline(fname, ebuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "Error opening file: %s\n", ebuf);
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
    
    pcap_close(pcap);
    return 0;
}
