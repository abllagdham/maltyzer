# maltyzer
## Malicious Traffic Analyzer

This tool was build to help reduce the time consumed on investigating pcap file for malicious traffic. It has two main functions file extraction and Malicious traffic detection.

1. File Extractor:

The tool extracts any file that was transferred over HTTP using tshark then calculates its SHA-1 hash value to check its existance on VirusTotal Database.

2. Malicious payload detector:

In this function, the tool extracts the payload from the traffic and compare it to a self-built signature database. The idea of building the signature DB came from IDS rules, where we just focus on the Layer 4 Protocol begin used to transfer the data and the payload patter for match.  


### Conseptual overview of the tool:
![alt text](https://raw.githubusercontent.com/abllagdham/maltyzer/main/Maltyzer.png)


The tool depends on two main things Scapy Framework and Tshark. It can be further enhanced to extend its capability.
