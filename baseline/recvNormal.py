#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import *

MIGRATION_PROTOCOL = 251
IPV4_PROTOCOL = 0x0800
TCP_PROTOCOL = 6

totalCount = 0

def handle_pkt(pkt):
    global totalCount

    if TCP in pkt:
        totalCount += 1

        str4tuple = str(pkt[IP].src)+" "+str(pkt[IP].dst)+" "+str(pkt[TCP].sport)+" "+str(pkt[TCP].dport)
        print str4tuple+" totalCount="+str(totalCount)

    sys.stdout.flush()


def main():

    iface = "h4-eth0"
    #iface = sys.argv[1]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
