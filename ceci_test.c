#include <pcap/pcap.h>

int main(int argc, char* argv) {

    //open file
    pcap_t *pcap_open_offline(char * fname, char * ebuf);

    //esnure file is captured from ethernet (should return 1)
    if (pcap_datalink(pcap_t *p) == 1) {

        //go through each packet from the file 
        int pcap_loop;
    }

}