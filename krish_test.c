//There will be code here
#include <stdio.h>
#include <pcap/pcap.h>

int main() {
    char ebuf[PCAP_ERRBUF_SIZE];
    const char *fname = "tcptext.txt";
    pcap_t *pcap;
    //open the input file
    pcap = pcap_open_offline(fname, ebuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "Error opening file: %s\n", ebuf);
        return 1;
    }

    int datalink = pcap_datalink(pcap);
    if (datalink == DLT_EN10MB)
        printf("Data is from 10MB ethernet!");
    else
        printf("Data is not from 10MB ethernet!");
    pcap_close(pcap);
    return 0;
}