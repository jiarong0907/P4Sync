from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512

import argparse
import sys
import socket
import random
import struct
import time
import base64
import binascii

from scapy.all import Packet, BitField, ShortField, IntField, bind_layers
from scapy.all import IP, TCP, sniff, sendp

# pip install pycryptodome


def rsa_sign(plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
    signer = PKCS1_v1_5.new(RSA.importKey(key))

    hash_value = hash_algorithm.new(plaintext)
    return signer.sign(hash_value)


def rsa_verify(sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
    hash_value = hash_algorithm.new(plaintext)
    verifier = PKCS1_v1_5.new(RSA.importKey(key))
    return verifier.verify(hash_value, sign)

def string2bits(s=''):
    return [bin(ord(x))[2:].zfill(8) for x in s]

def bits2string(b=None):
    return ''.join([chr(int(x, 2)) for x in b])


MIGRATION_PROTOCOL = 251
SIGNATURE_PROTOCOL = 253
IPV4_PROTOCOL = 0x0800
TCP_PROTOCOL = 6

private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD1t3KRf4oS3sH8PbABbXL1KBYCnGq4C/yinpfQ2j2eUmZarHuw
IMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjglAgVEb3el6iU+WZ7nwLub/BN
YS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpEI/0b+EfRSpXDdvU64wIDAQAB
AoGBAJK0odHfPTgBCf8pcaGYkG9xLJsIeutCNOd/GxOWif2yIux2WS8SkasaWd+/
J5iCSD32t4G9dafSNZyvtTPGYUqll4aGXlFqNW8pm16HPQXWrhv1D5LVEEu3zbj+
iNG+gHwB4bISQAOJbnvB6GoFUbDf8VYwkGGlSLGw5D5tulhRAkEA/XBLTfj+5j40
QPfuRIhcBsgxynKJDcmV0sLAIOTBIfSKs5nuYHEVEOcGaxS+nPY3w1ffSUPUdxm0
7L2s+9c0SQJBAPgzLLFvUjM58J/AtklkGyJ3KK5W+jLi/N1PIw7CGYGM2yfFiQLR
ibtJVjTFhLKqDz/BK4lZ9ffU/VNHSApOncsCQQCRBzSgnw9GtGv0jaxUnW+EFgWg
IyDYufW5kOafLCh1BNpmYnztxWhXrsyWdF2Ltr48U8mbxGwN57EIFJar2v+5AkA7
GkSMRAv48tUf1Y4Sz+m+PU3Mph2SPIcmVA/vFb1pIheV0u4bY7Y+iOokStychu52
qhMp8+gkie2BBTpcafgdAkBw8bAzLgmCV8SZEN60x8c2M2Y95CoYOoMLjvQdEfen
IeDmun3DtAPBuStwYNfeQnAHCwvcOJsgDiRLzhys3056
-----END RSA PRIVATE KEY-----'''

public_key = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1t3KRf4oS3sH8PbABbXL1KBYC
nGq4C/yinpfQ2j2eUmZarHuwIMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjg
lAgVEb3el6iU+WZ7nwLub/BNYS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpE
I/0b+EfRSpXDdvU64wIDAQAB
-----END PUBLIC KEY-----'''

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

class Signature(Packet):
    name = "Signature"
    fields_desc = [BitField("protocol", 0, 8),
        BitField("signature", 0, 1024)]

bind_layers(IP, Migration, proto = MIGRATION_PROTOCOL)
bind_layers(Migration, Signature, protocol = SIGNATURE_PROTOCOL)
bind_layers(Migration, TCP, protocol = TCP_PROTOCOL)
bind_layers(Signature, TCP, protocol = TCP_PROTOCOL)


def handle_pkt(pkt):
    global totalCount

    #pkt.show2()

    if Migration in pkt and int(pkt["Signature"].protocol) == 1:
        print "got a packet"
        print "====================="

        pkt.show2()
        proto = str(pkt["Migration"].protocol)
        index = str(pkt["Migration"].index)
        state = str(pkt["Migration"].state)
        message = proto+index+state
        signature = rsa_sign(message.encode(encoding='utf-8'), private_key)

        bi = string2bits(signature)
        encode = ""
        for i in range(len(bi)):
            encode += bi[i]

        pkt["Signature"].signature = long(encode, 2)
        pkt["Signature"].protocol = TCP_PROTOCOL
        pkt.show2()
        sendp(pkt, iface="h3-eth0", verbose=False)


    sys.stdout.flush()


if __name__ == '__main__':

    iface = "h3-eth0"
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: handle_pkt(x))

    message = "proto+index+state"
    signature = rsa_sign(message.encode(encoding='utf-8'), private_key)