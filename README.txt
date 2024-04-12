# project1_cs3516
Project 1 CS 3516 - Krish Patel, Ceci Herriman

Our project is a packet analyzer that takes in a packet capture 
file, and prints out statistics and summaries about the packets
in the capture. For each packet, the program returns the date, 
time, duration since first packet, and length. It also prints all of the 
ethernet source and destination addresses with the number of occurences for 
each. If the packet has associated ip source and destination addresses, it
prints those with the # of occurences as well. The analyzer can also detect
if ARP or UDP is in use, and prints machine MAC and IP addresses for senders and 
recipients in ARP along with source and destination ports for UDP usages.
All addresses printed have associated occurence values. Finally, the 
analyzer returns the total number of packets processed, along 
with the average, minimum, and maxiumum packet lengths. 

To specify a .pcap file to be analyzed, change the "fname" variable 
value in near the top of the main() fuction to the name of your file. 

To run the program, type "make" in your terminal. You can also 
run "make clean" and "make all".
