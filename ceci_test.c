#include <pcap/pcap.h>

int main(int argc, char* argv) {
    char ebuf[PCAP_ERRBUF_SIZE];
    const char *fname = "project2-dns.pcap";
    pcap_t *pcap;

    void pcap_handler(const u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
        //implementation here
    }
    
    //open the input file
    pcap = pcap_open_offline(fname, ebuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "Error opening file: %s\n", ebuf);
        return 1;
    }

    int datalink = pcap_datalink(pcap);
    if (datalink == DLT_EN10MB) {
        printf("Data is from 10MB ethernet!");
        int pcap_loop(pcap, 1, pcap_callback, u_char *user); 
    }
    else {
        printf("Data is not from 10MB ethernet!");
    pcap_close(pcap);
    return 0;
    }
}