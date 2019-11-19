## Project 2 - Analyze Packets
### Contributors: 
Jack Gerulskis and Winny Cheng

### Overview

This project uses the Packet Capture Library to read captured packet datas, anaylzes the packets, and outputs the following statistics:
- Start data and time of packet capture
- Duration of packet capture in seconds
- Total number of packets
- Unique Senders and Recipients
- Machines participating in ARP
- Unique source ports and destination ports
- Average, minimum, and maximum packet sizes

#### How to use

- run the makefile via 'make'
- run the wireview executable with a .pcap file
    > example command: ./wireview http.pcap

### Other-network.pcap