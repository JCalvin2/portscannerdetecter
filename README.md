# portscannerdetecter
Detects Port Scanning with PCAP file as Input
This code takes a pcap file as input from the command line, reads it, and tells which IPs are ports scanning.
If an IP has 3 times as many SYNs as SYN/ACKs, then it is flagged as scanning. 
