#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import *


MIGRATION_PROTOCOL = 251
IPV4_PROTOCOL = 0x0800
TCP_PROTOCOL = 6

class Migration(Packet):
    name = "Migration"
    fields_desc = [BitField("protocol", 0, 8),
        BitField("stage", 0, 8),
        ShortField("index", 0),
        IntField("state", 0),
        BitField("mac", 0, 64),
        IntField("verify", 0),
        ShortField("mainProg", 0),
        ShortField("deltaProg", 0)]

bind_layers(IP, Migration, proto = MIGRATION_PROTOCOL)
bind_layers(Migration, TCP, protocol = TCP_PROTOCOL)

def sendMigratePacket(sock, text, s, indx):
    splitArray = text.split(" ")

    srcIP = splitArray[0]
    dstIP = splitArray[1]
    srcPort = splitArray[2]
    dstPort = splitArray[3]

    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', type = IPV4_PROTOCOL)
    pkt = pkt / IP(src=srcIP, dst=dstIP, proto=MIGRATION_PROTOCOL) / Migration(protocol = TCP_PROTOCOL, stage = s, index = indx) / TCP(sport=int(srcPort), dport=int(dstPort)) / "textaaa"
    time.sleep(0.001)
    sock.send(pkt)



def main():
    start_time = time.time()

    traces = []
    REGISTER_SIZE = 1024
    MAX_NUM = REGISTER_SIZE * 1
    iface = "h2-eth0"

    s = conf.L2socket(iface=iface)

    filepath = '../trace.data'
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            traces.append(line.replace("\n",""))
            line = fp.readline()

    index = 0
    for i in range(MAX_NUM):
        sendMigratePacket(s, traces[i], 1, index)
        index += 1
        print i

    index = 0
    for i in range(MAX_NUM):
        sendMigratePacket(s, traces[i], 2, index)
        index += 1
        print i

    end_time = time.time()
    print "Time = "+str(end_time - start_time)

if __name__ == '__main__':
    main()
