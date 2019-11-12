#include <iostream>
#include <string.h>
#include <pcap/pcap.h>
#include <cstddef>

// start date and time of packet capture
// duration of capture in seconds.microseconds
// total
// unique senders, total # of packets sent
//		^ use hex-colon for ethernet, dot notation for IP
// unique receivers, total # of packets received
//		^ use hex-colon for ethernet, dot notation for IP
// create list of machines partcipating in "ARP", their mac and ip if possible
// for udp unique destination ports
// for udp unique source ports
// avg, min, and max packet size
struct packetCaptureData {
	u_int count;
};

/**
* Callback function for pcap_loop()
*/
void analyzePacket(u_char* a, const struct pcap_pkthdr* b, const u_char *c) {
	std::cout << "Packet of size " << b->caplen << " received at " << b->ts.tv_sec << std::endl;
}

/**
 * Main function for the program
 * 
 * Run as ./wireview filePath
 */
int main(int argc, char* argv[]) {
	std::string filePath;
	pcap_t* file;
	const int ETHERNET = 1;
	const int MAX_PACKETS_TO_READ = 0; // read to eof
	
	
	if (argc != 2) { // enforce that only 1 file was given
		std::cout << "Please run as ./wireview filePath" << std::endl;
		return -1;
	}
	filePath = argv[1];

	// let's try and open the file now
	char errbuf[PCAP_ERRBUF_SIZE];
	file = pcap_open_offline(filePath.c_str(), errbuf);
	if (file == NULL) { // check if file was successfully opened
		std::cout << errbuf << std::endl;
		return -1;
	}
	
	// check if network layer has ethernet header
	if (pcap_datalink(file) != ETHERNET) {
		std::cout << "Packets were not captured from ethernet" << std::endl;
	}
	
	std::cout << "Received a valid packet capture" << std::endl;
	if (pcap_loop(file, MAX_PACKETS_TO_READ, analyzePacket, NULL) < 0) {
		std::cout << "pcap_loop() failed: " << pcap_geterr(file) << std::endl;
	}
	std::cout << "Finished reading packet capture" << std::endl;
	pcap_close(file);
	
}