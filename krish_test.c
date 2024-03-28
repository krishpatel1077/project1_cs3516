//There will be code here
#include <stdio.h>
#include <pcap/pcap.h>

void my_packet_handler()
{

}
int main() {
    char ebuf[PCAP_ERRBUF_SIZE];
    const char *fname = "project2-dns.pcap";
    pcap_t *pcap;
    //open the input file
    pcap = pcap_open_offline(fname, ebuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "Error opening file: %s\n", ebuf);
        return 1;
    }

    int datalink = pcap_datalink(pcap);
    if (datalink == DLT_EN10MB)
    {
        printf("Data is from 10MB ethernet!");
        //try to the pcap loop here
        
    }
    else
        printf("ERROR! DATA NOT FROM ETHERNET");
    
    pcap_close(pcap);
    return 0;
}