from scapy.all import *
import math

NS3DEBUG_PROTOCOL = 251

path_prefix = "./build/s1-eth5_in.pcap"

def analyze_pcap():

	# rdpcap comes from scapy and loads in our pcap file
    filename = path_prefix
    print "Reading pcap from "+filename

    packets = rdpcap(filename)
    last_prog = -1
    totalcount = 0

    print "The number of packets is "+str(len(packets))
    for i in range(len(packets)):
        pkt = packets[i]
        # pkt.show2()

        if pkt["IP"].proto == 251:
            totalcount += 1
            #pkt.show2()
            #print pkt["Debug"].seqNo

            #if int(str(struct.unpack('>I', pkt[Raw].load[4:8])[0]))>last_prog:
            print "totalcount: "+str(totalcount)+" progVal: " + str(struct.unpack('>I', pkt[Raw].load[4:8])[0])
            last_prog = int(str(struct.unpack('>I', pkt[Raw].load[4:8])[0]))



			# print "got a packet"
			# print "====================="
			# print "state: " + str(struct.unpack('>I', pkt[Raw].load[0:4])[0])
			# print "progVal: " + str(struct.unpack('>I', pkt[Raw].load[4:8])[0])
			# print "next_type: " + str(struct.unpack('>I', pkt[Raw].load[8:12])[0])
			# print "protocol: " + str(struct.unpack('>I', pkt[Raw].load[12:16])[0])



if __name__ == "__main__":
	analyze_pcap()
