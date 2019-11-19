#include <iostream>
#include <string.h>
#include <pcap/pcap.h>
#include <cstddef>
#include <arpa/inet.h>

#define MAC_ADDRESSS_LENGTH 6

typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* Ethernet Header */
typedef struct ethernet_header {
	u_char ether_dhost[6]; // ETH address
	u_char ether_shost[6];
	u_short ether_type; // ARP Stored here
}ethernet_header;

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

typedef struct uniqueUser {
	ip_address ipAddr;
	u_int numPackets;

}uniqueUser;

typedef struct arpComputers{
	u_char macAddress[6];
	ip_address ipAddress;
}arpComputers;

typedef struct packetCaptureData {
	struct timeval startDateAndTime;
	struct timeval endDateAndTime;
	double duration; // must be computed at end
	u_int total;
	uniqueUser *uniqueSenders;
	u_int uniqueSenderSize; 
	uniqueUser *uniqueRecipients;
	u_int uniqueRecipientSize; 
	u_int *udpUniqueSourcePorts;
	u_int uniqueSourcePortSize;
	u_int *udpUniqueDestinationPorts;
	u_int uniqueDestinationPortSize;
	u_char uniqueSenderMacAddress[100][6]; // oh this is so bad
	int uniqueSenderMacPackets[100];
	u_int uniqueSendersMac;
	u_char uniqueRecipientMacAddress[100][6];
	int uniqueRecipientsMacPackets[100];
	u_int uniqueRecipientsMac;
	arpComputers uniqueARPComputers[100];
	u_int uniqueARPCount;
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
	uniqueUser *newArr = new uniqueUser[size + 1];
	for (int i = 0; i < size; i++){
		uniqueUser sender = data.uniqueSenders[i];
		newArr[i].ipAddr = sender.ipAddr;
		newArr[i].numPackets = sender.numPackets;

		if(sender.ipAddr.byte1 == senderIP.byte1 && sender.ipAddr.byte2 == senderIP.byte2 &&
			sender.ipAddr.byte3 == senderIP.byte3 && sender.ipAddr.byte4 == senderIP.byte4){
			newArr[i].numPackets++;
			unique = false;
		}
	}
	if(unique){
		newArr[size].ipAddr = senderIP;
		newArr[size].numPackets = 1;
		data.uniqueSenderSize++;
	}
	delete[] data.uniqueSenders;
	data.uniqueSenders = newArr;
}

void updateUniqueRecipients(packetCaptureData &data, ip_address RecipientsIP) {
	// TODO: implement
	bool unique = true;

	int size = data.uniqueRecipientSize;
	uniqueUser *newArr = new uniqueUser[size + 1];
	for (int i = 0; i < size; i++){
		uniqueUser sender = data.uniqueRecipients[i];
		ip_address addr = sender.ipAddr;
		newArr[i].ipAddr = addr;
		newArr[i].numPackets = sender.numPackets;

		if(addr.byte1 == RecipientsIP.byte1 && addr.byte2 == RecipientsIP.byte2 &&
			addr.byte3 == RecipientsIP.byte3 && addr.byte4 == RecipientsIP.byte4){
			newArr[i].numPackets++;
			unique = false;
		}
	}
	if(unique){
		newArr[size].ipAddr = RecipientsIP;
		newArr[size].numPackets = 1;
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
 * Helper method to compare char arrays of size 6, useful for mac addresses
 */
bool isEqualCharArray(u_char arr1[6], u_char arr2[6]) {
	for (int i = 0; i < 6; i++) if (arr1[i] != arr2[i]) return false;
	return true;
}

void updateUniqueReceiverMacAddresses(packetCaptureData &data, u_char macAddress[MAC_ADDRESSS_LENGTH]) {
	if (!data.uniqueRecipientsMac) data.uniqueRecipientsMac = 0;
	for (u_int i = 0; i < data.uniqueRecipientsMac; i++) {
		if (isEqualCharArray(data.uniqueRecipientMacAddress[i], macAddress)) {
			data.uniqueRecipientsMacPackets[i] += 1;
			return; // found a similar one
		}
	}
	// no match found
	for (int i = 0; i < MAC_ADDRESSS_LENGTH; i++) data.uniqueRecipientMacAddress[data.uniqueRecipientsMac][i] = macAddress[i];
	data.uniqueRecipientsMacPackets[data.uniqueRecipientsMac] = 1;
	data.uniqueRecipientsMac++;
}

void updateUniqueSendersMacAddresses(packetCaptureData &data, u_char macAddress[MAC_ADDRESSS_LENGTH]) {
	if (!data.uniqueSendersMac) data.uniqueSendersMac = 0;
	for (u_int i = 0; i < data.uniqueSendersMac; i++) {
		if (isEqualCharArray(data.uniqueSenderMacAddress[i], macAddress)) {
			data.uniqueSenderMacPackets[i] += 1;
			return; // found a similar one
		}
	}
	// no match found
	for (int i = 0; i < MAC_ADDRESSS_LENGTH; i++) data.uniqueSenderMacAddress[data.uniqueSendersMac][i] = macAddress[i];
	data.uniqueSenderMacPackets[data.uniqueSendersMac] = 1;	
	data.uniqueSendersMac++;
}

void updateUniqueARPComputers(packetCaptureData &data, u_char macAddress[MAC_ADDRESSS_LENGTH], ip_address ipAdrress) {
	if (!data.uniqueARPCount) data.uniqueARPCount = 0;
	for (u_int i = 0; i < data.uniqueARPCount; i++) {
		if (isEqualCharArray(data.uniqueARPComputers[i].macAddress, macAddress)) {
			if (data.uniqueARPComputers[i].ipAddress.byte1 == ipAdrress.byte1 &&
				data.uniqueARPComputers[i].ipAddress.byte2 == ipAdrress.byte2 &&
				data.uniqueARPComputers[i].ipAddress.byte3 == ipAdrress.byte3 &&
				data.uniqueARPComputers[i].ipAddress.byte4 == ipAdrress.byte4) {
				return; // found a match
			}
		}
	}
	// no match found
	for (int i = 0; i < MAC_ADDRESSS_LENGTH; i++) data.uniqueARPComputers[data.uniqueARPCount].macAddress[i] = macAddress[i];
	data.uniqueARPComputers[data.uniqueARPCount].ipAddress = ipAdrress;
	data.uniqueARPCount++;
}

/**
 * Source: https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut6.html
 */
void updateUniqueSendersAndReceiversIPandPorts(packetCaptureData &data, const u_char *packetData) {
	ethernet_header *eh;
	ip_header *ih;
    udp_header *uh;
	u_int ip_len;
    u_short sport,dport;

	/* retrieve the position of the eth header */
	eh = (ethernet_header *) (packetData);

	/* retireve the position of the ip header */
    ih = (ip_header *) (packetData + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

	updateUniqueSenders(data, ih->saddr);
	updateUniqueRecipients(data, ih->daddr);
	updateudpUniqueSourcePorts(data, sport);
	updateudpUniqueDestinationPorts(data, dport);
	updateUniqueReceiverMacAddresses(data, eh->ether_dhost);
	updateUniqueSendersMacAddresses(data, eh->ether_shost);
	if (eh->ether_type == 8) updateUniqueARPComputers(data, eh->ether_shost, ih->saddr); // double check comparison
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
	std::cout << "\tIP:" << std::endl;
	for(u_int i = 0; i < data.uniqueSenderSize; i++){
		uniqueUser sender = data.uniqueSenders[i];
		printf("\t %d.%d.%d.%d",
        	sender.ipAddr.byte1,
        	sender.ipAddr.byte2,
        	sender.ipAddr.byte3,
        	sender.ipAddr.byte4);
		std::cout << "\t\tPackets Sent:: " << sender.numPackets << std::endl;
	}
	std::cout << "\tMAC:" << std::endl;
	for (u_int i = 0; i < data.uniqueSendersMac; i++) {
		printf("\t %02x:%02x:%02x:%02x:%02x:%02x \tPackets Sent: %d\n",
  			data.uniqueSenderMacAddress[i][0],
  			data.uniqueSenderMacAddress[i][1],
  			data.uniqueSenderMacAddress[i][2],
  			data.uniqueSenderMacAddress[i][3],
  			data.uniqueSenderMacAddress[i][4],
  			data.uniqueSenderMacAddress[i][5],
			data.uniqueSenderMacPackets[i]);
	}
	std::cout << "Unique Recipients: " << std::endl;
	std::cout << "\tIP:" << std::endl;
	for(u_int i = 0; i < data.uniqueRecipientSize; i++){
		uniqueUser recipient = data.uniqueRecipients[i];
		printf("\t %d.%d.%d.%d",
        	recipient.ipAddr.byte1,
        	recipient.ipAddr.byte2,
        	recipient.ipAddr.byte3,
        	recipient.ipAddr.byte4);
		std::cout << "\t\t Packets Received: " << recipient.numPackets << std::endl;
	}
	std::cout << "\tMAC:" << std::endl;
	for (u_int i = 0; i < data.uniqueRecipientsMac; i++) {
		printf("\t %02x:%02x:%02x:%02x:%02x:%02x \tPackets Received: %d\n",
  			data.uniqueRecipientMacAddress[i][0],
  			data.uniqueRecipientMacAddress[i][1],
  			data.uniqueRecipientMacAddress[i][2],
  			data.uniqueRecipientMacAddress[i][3],
  			data.uniqueRecipientMacAddress[i][4],
  			data.uniqueRecipientMacAddress[i][5],
			data.uniqueRecipientsMacPackets[i]);
	}
	// list of machines participating in arp
	std::cout << "UDP Unique Source Ports: " << std::endl;
	for(u_int i = 0; i < data.uniqueSourcePortSize; i++){
		printf("\t %d \n",
        	data.udpUniqueSourcePorts[i]);
	}
	std::cout << "UDP Unique Destination Ports: " << std::endl;
	for(u_int i = 0; i < data.uniqueDestinationPortSize; i++){
		printf("\t %d \n",
        	data.udpUniqueDestinationPorts[i]);
	}
	std::cout << "Computers Participating in ARP:" << std::endl;
	for (u_int i = 0; i < data.uniqueARPCount; i++) {
		printf("\t MAC: %02x:%02x:%02x:%02x:%02x:%02x IP: %d.%d.%d.%d\n",
  			data.uniqueARPComputers[i].macAddress[0],
  			data.uniqueARPComputers[i].macAddress[1],
  			data.uniqueARPComputers[i].macAddress[2],
  			data.uniqueARPComputers[i].macAddress[3],
  			data.uniqueARPComputers[i].macAddress[4],
  			data.uniqueARPComputers[i].macAddress[5],
			data.uniqueARPComputers[i].ipAddress.byte1,
        	data.uniqueARPComputers[i].ipAddress.byte1,
        	data.uniqueARPComputers[i].ipAddress.byte1,
        	data.uniqueARPComputers[i].ipAddress.byte1);
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