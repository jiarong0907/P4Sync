#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import *


IPV4_PROTOCOL = 0x0800

def sendPacket(sock, text):
    splitArray = text.split(" ")
    srcIP = splitArray[0]
    dstIP = splitArray[1]
    srcPort = splitArray[2]
    dstPort = splitArray[3]


    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', type = IPV4_PROTOCOL)
    pkt = pkt / IP(src=srcIP, dst=dstIP) / TCP(sport=int(srcPort), dport=int(dstPort)) / "text"
    time.sleep(0.001) # prevent packet loss caused by sending too fast
    sock.send(pkt)


def main():
    start_time = time.time()

    traces = []
    REGISTER_SIZE = 1024
    MAX_NUM = REGISTER_SIZE * 8
    iface = "h1-eth0"

    s = conf.L2socket(iface=iface)

    filepath = '../trace.data'
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            traces.append(line.replace("\n",""))
            line = fp.readline()


    for i in range(MAX_NUM):
        sendPacket(s, traces[i])
        if (i%1000 == 0):
            print i/REGISTER_SIZE

    end_time = time.time()
    print "Time = "+str(end_time - start_time)

if __name__ == '__main__':
    main()
