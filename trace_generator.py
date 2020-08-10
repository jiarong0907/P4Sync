#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

IPV4_PROTOCOL = 0x0800


def main():

    runs = 1000000


    result = []
    for _ in range(runs):
        srcIP = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        dstIP = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        srcPort = random.randint(0, 65535)
        dstPort = random.randint(0, 65535)

        result.append(srcIP+" "+dstIP+" "+str(srcPort)+" "+str(dstPort))

    f= open("trace1.data","w+")
    for i in range(len(result)):
        f.write(result[i]+"\n")

    f.close()


if __name__ == '__main__':
    main()
