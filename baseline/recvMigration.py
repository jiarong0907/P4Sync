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
    fields_desc = [IntField("state", 0),
                    IntField("progVal", 0),
                    IntField("next_type", 0),
                    IntField("protocol", 0)
                   ]

bind_layers(IP, Migration, proto = MIGRATION_PROTOCOL)
bind_layers(Migration, TCP, protocol = TCP_PROTOCOL)

totalCount = 0
lastProg = -1

def handle_pkt(pkt):
    global totalCount, lastProg

    if Migration in pkt:
        totalCount += 1
        str4tuple = str(pkt[IP].src)+" "+str(pkt[IP].dst)+" "+str(pkt[TCP].sport)+" "+str(pkt[TCP].dport)
        print "totalCount="+str(totalCount)+" progress="+str(pkt["Migration"].progVal)
        lastProg = int(pkt["Migration"].progVal)


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
