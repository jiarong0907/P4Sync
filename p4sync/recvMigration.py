#!/usr/bin/env python
import sys
import struct
import os

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

totalCount = 0

def handle_pkt(pkt):
    global totalCount

    if Migration in pkt:
        totalCount += 1

        str4tuple = str(pkt[IP].src)+" "+str(pkt[IP].dst)+" "+str(pkt[TCP].sport)+" "+str(pkt[TCP].dport)
        if (pkt["Migration"].stage == 1):
            print " totalCount="+str(totalCount)+" stage="+str(pkt["Migration"].stage)+" progress="+str(pkt["Migration"].mainProg)+" verify="+str(pkt["Migration"].verify)
        elif (pkt["Migration"].stage == 2):
            print " totalCount="+str(totalCount)+" stage="+str(pkt["Migration"].stage)+" progress="+str(pkt["Migration"].deltaProg)+" verify="+str(pkt["Migration"].verify)
    sys.stdout.flush()


def main():

    iface = "h5-eth0"
    #iface = sys.argv[1]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
