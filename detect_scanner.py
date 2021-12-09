#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dpkt, sys, socket

tcpPackets = dict() #Contains IPs, SYN count, and SYN-ACK count

f = open(sys.argv[1], "rb") #pcap file as input - command line input
pcap = dpkt.pcap.Reader(f)

packet = 0

for ts, buf in pcap:

    packet += 1
    try: #error checking eth
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
    except(dpkt.dpkt.UnpackError, IndexError):
        continue

    ip = eth.data #error checking IP
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        continue

    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP: #Check if packet is TCP
        continue

    #setting the src and dst
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)

    #if there are syn/ack and syn, add to dict
    if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
        if dst not in tcpPackets:
            tcpPackets[dst] = {'SYN': 0, 'SYN-ACK': 0}
        tcpPackets[dst]['SYN-ACK'] += 1

    elif (tcp.flags & dpkt.tcp.TH_SYN):
        if src not in tcpPackets: 
            tcpPackets[src] = {'SYN': 0, 'SYN-ACK': 0}
        tcpPackets[src]['SYN'] += 1

#output the set of IP addresses (one per line) that sent more than 3 times as many SYN packets as the number of SYN+ACK packets they received, if not then del from the dict.
for i in list(tcpPackets):
        if tcpPackets[i]['SYN'] < (tcpPackets[i]['SYN-ACK'] * 3):
            del tcpPackets[i]

if not tcpPackets:
    print("Nothing wrong here")

else:
    for i in tcpPackets.keys():
        print(i)
