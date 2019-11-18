#include <iostream>
#include <string.h>
#include <pcap/pcap.h>
#include <cstddef>
#include <arpa/inet.h>

typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

typedef struct computerInfo {
	ip_address ipAddress;
	std::string macAddress;
}computerInfo;

typedef struct packetCaptureData {
	struct timeval startDateAndTime;
	struct timeval endDateAndTime;
	double duration; // must be computed at end
	u_int total;
	ip_address *uniqueSenders;
	u_int uniqueSenderSize; 
	ip_address *uniqueRecipients;
	u_int uniqueRecipientSize; 
	computerInfo *computers;
	u_int *udpUniqueSourcePorts;
	u_int uniqueSourcePortSize;
	u_int *udpUniqueDestinationPorts;
	u_int uniqueDestinationPortSize;
	u_int minPacketSize;
	u_int maxPacketSize; 
	u_int sumPacketSize;
	u_int avgPacketSize; // must be computed at end
}packetCaptureData;

packetCaptureData data;

void setStartDate(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	data.startDateAndTime = packet->ts;
}

void updateDuration(packetCaptureData &data){
	struct timeval diff = {
		data.endDateAndTime.tv_sec - data.startDateAndTime.tv_sec,
		data.endDateAndTime.tv_usec - data.startDateAndTime.tv_usec
	};
	data.duration = diff.tv_sec + diff.tv_usec / 1000000.0;
}

void updateEndTime(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	data.endDateAndTime = packet->ts;
}

void updateTotal(packetCaptureData &data) {
	data.total++;
}

void updateUniqueSenders(packetCaptureData &data, ip_address senderIP) {
	// TODO: implement
	bool unique = true;

	int size = data.uniqueSenderSize;
	ip_address *newArr = new ip_address[size + 1];
	for (int i = 0; i < size; i++){
		ip_address addr = data.uniqueSenders[i];
		newArr[i] = addr;
		if(addr.byte1 == senderIP.byte1 && addr.byte2 == senderIP.byte2 &&
			addr.byte3 == senderIP.byte3 && addr.byte4 == senderIP.byte4){
			unique = false;
		}
	}
	if(unique){
		newArr[size] = senderIP;
		data.uniqueSenderSize++;
	}

	delete[] data.uniqueSenders;
	data.uniqueSenders = newArr;
}

void updateUniqueRecipients(packetCaptureData &data, ip_address RecipientsIP) {
	// TODO: implement
	bool unique = true;

	int size = data.uniqueRecipientSize;
	ip_address *newArr = new ip_address[size + 1];
	for (int i = 0; i < size; i++){
		ip_address addr = data.uniqueRecipients[i];
		newArr[i] = addr;
		if(addr.byte1 == RecipientsIP.byte1 && addr.byte2 == RecipientsIP.byte2 &&
			addr.byte3 == RecipientsIP.byte3 && addr.byte4 == RecipientsIP.byte4){
			unique = false;
		}
	}
	if(unique){
		newArr[size] = RecipientsIP;
		data.uniqueRecipientSize++;
	}

	delete[] data.uniqueRecipients;
	data.uniqueRecipients = newArr;
}

void updateudpUniqueSourcePorts(packetCaptureData &data, u_short sourcePort) {
	// TODO: implement
	bool unique = true;

	int size = data.uniqueSourcePortSize;
	u_int *newArr = new u_int[size + 1];
	for (int i = 0; i < size; i++){
		u_int port = data.udpUniqueSourcePorts[i];
		newArr[i] = port;
		if(sourcePort == port){
			unique = false;
		}
	}
	if(unique){
		newArr[size] = sourcePort;
		data.uniqueSourcePortSize++;
	}

	delete[] data.udpUniqueSourcePorts;
	data.udpUniqueSourcePorts = newArr;
}

void updateudpUniqueDestinationPorts(packetCaptureData &data, u_short desitinationPort) {
	// TODO: implement
	bool unique = true;

	int size = data.uniqueDestinationPortSize;
	u_int *newArr = new u_int[size + 1];
	for (int i = 0; i < size; i++){
		u_int port = data.udpUniqueDestinationPorts[i];
		newArr[i] = port;
		if(desitinationPort == port){
			unique = false;
		}
	}
	if(unique){
		newArr[size] = desitinationPort;
		data.uniqueDestinationPortSize++;
	}

	delete[] data.udpUniqueDestinationPorts;
	data.udpUniqueDestinationPorts = newArr;
}

/**
 * Source: https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut6.html
 */
void updateUniqueSendersAndReceiversIPandPorts(packetCaptureData &data, const u_char *packetData) {
	
	ip_header *ih;
    udp_header *uh;
	u_int ip_len;
    u_short sport,dport;
	/* retireve the position of the ip header */
    ih = (ip_header *) (packetData + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);

	updateUniqueSenders(data, ih->saddr);
	updateUniqueRecipients(data, ih->daddr);
	updateudpUniqueSourcePorts(data, sport);
	updateudpUniqueDestinationPorts(data, dport);
}

void updataMinPacketSize(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	if (data.minPacketSize > packet->len || !data.minPacketSize) {
		data.minPacketSize = packet->len;
	}
}

void updataMaxPacketSize(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	if (data.maxPacketSize < packet->len) {
		data.maxPacketSize = packet->len;
	}
}

void updataSumPacketSize(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	data.sumPacketSize += packet->len;
}

void updateAvgPacketSize(packetCaptureData &data, const struct pcap_pkthdr* packet) {
	data.avgPacketSize = data.sumPacketSize / data.total;
}


/**
* Callback function for pcap_loop()
*/
void analyzePacket(u_char* a, const struct pcap_pkthdr* b, const u_char *c) {
	if(!data.startDateAndTime.tv_sec){
		setStartDate(data, b);
	}
	updateEndTime(data, b);
	updateDuration(data);
	updateTotal(data);
	updataMinPacketSize(data, b);
	updataMaxPacketSize(data, b);
	updataSumPacketSize(data, b);
	updateAvgPacketSize(data, b);
	updateUniqueSendersAndReceiversIPandPorts(data, c);
}

void printPacketCaptureReport(packetCaptureData &data) {
	std::cout << "___***PACKET_CAPTURE_REPORT***___" << std::endl << std::endl;
	time_t time = (time_t)data.startDateAndTime.tv_sec;
	std::cout << "Start date and time: \t" << ctime(&time);
	std::cout << "Duration: \t\t" << data.duration << "s" << std::endl;
	std::cout << "Total packets: \t\t" << data.total << std::endl;
	std::cout << "Unique Senders: " << std::endl;
	for(int i = 0; i < data.uniqueSenderSize; i++){
		printf("\t %d.%d.%d.%d \n",
        	data.uniqueSenders[i].byte1,
        	data.uniqueSenders[i].byte2,
        	data.uniqueSenders[i].byte3,
        	data.uniqueSenders[i].byte4);
	}
	std::cout << "Unique Recipients: " << std::endl;
	for(int i = 0; i < data.uniqueRecipientSize; i++){
		printf("\t %d.%d.%d.%d \n",
        	data.uniqueRecipients[i].byte1,
        	data.uniqueRecipients[i].byte2,
        	data.uniqueRecipients[i].byte3,
        	data.uniqueRecipients[i].byte4);
	}
	// list of machines participating in arp
	std::cout << "UDP Unique Source Ports: " << std::endl;
	for(int i = 0; i < data.uniqueSourcePortSize; i++){
		printf("\t %d \n",
        	data.udpUniqueSourcePorts[i]);
	}
	std::cout << "UDP Unique Destination Ports: " << std::endl;
	for(int i = 0; i < data.uniqueDestinationPortSize; i++){
		printf("\t %d \n",
        	data.udpUniqueDestinationPorts[i]);
	}
	std::cout << "Average packet size: \t" << data.avgPacketSize << std::endl;
	std::cout << "Minimum packet size: \t" << data.minPacketSize << std::endl;
	std::cout << "Maximum packet size: \t" << data.maxPacketSize << std::endl;

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
	std::cout << "Finished reading packet capture\n" << std::endl;
	printPacketCaptureReport(data);
	pcap_close(file);
}