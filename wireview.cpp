#include <iostream>
#include <string.h>
#include <pcap/pcap.h>
#include <cstddef>

int main(int argc, char* argv[]) {
	std::string filePath;
	pcap_t* file;
	const int ETHERNET = 1;
	
	
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
	
}

/**
* Callback function for pcap_loop()
*/
void analyzePacket(u_char* a, const struct pcap_pkthdr* b, const u_char *c) {
	
}