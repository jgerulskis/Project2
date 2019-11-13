#include <iostream>
#include <string.h>
#include <pcap/pcap.h>
#include <cstddef>

struct packetCaptureData {
	std::string startDateAndTime;
	double duration; // seconds.ms
	u_int total;
	std::string *uniqueSenders; 
	std::string *uniqueRecipients;
	struct computerInfo *computers;
	u_int *udpUniqueSourcePorts;
	u_int *udpUniqueDestinationPorts;
	u_int minPacketSize;
	u_int maxPacketSize;
	u_int avgPacketSize;
};

struct computerInfo {
	std::string ipAddress;
	std::string macAddress;
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