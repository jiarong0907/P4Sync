/* -*- P4_16 -*- */


#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x0800;


#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#include "./includes/common.p4"

const bit<8>  TCP_PROTOCOL = 6;
const bit<8>  MIGRATION_PROTOCOL = 251;
const bit<8>  ICMP_PROTOCOL = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header migration_t {
    bit<32> state;
    bit<32> progVal;
    bit<32> next_type;
    bit<32> protocol;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    migration_t[1]   migration;
    tcp_t      tcp;
}

struct metadata {
    bit<16> progVal; // the migration progress, pass to egress
    bit<32> migrateState; // the migration state, pass to egress
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4           :parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL   : parse_tcp;
            MIGRATION_PROTOCOL: parse_migration;
            default: accept;
        }
    }

    state parse_migration {
        packet.extract(hdr.migration.next);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // The register to be migrated, count the number of packets of each flow
    register <bit<32>>(REGISTER_SIZE) flowsize;
    // Use this register array to record which entry has been hit by normal flow to compute completeness
    register <bit<32>>(REGISTER_SIZE) ishit;
    // The migration progress, record how many dirty entries have been migrated
    register <bit<16>>(1) progress;


    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0 && hdr.ipv4.protocol == TCP_PROTOCOL){
            // packets from TCP sender
            if (standard_metadata.ingress_port == 1){

                // forward to h4
                standard_metadata.egress_spec = 4;

                bit<32> index;
                hash(index, HashAlgorithm.crc16, (bit<32>)0,
                    {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)REGISTER_SIZE);

                bit<32> ishitVal;
                ishit.read(ishitVal, index);
                progress.read(meta.progVal, 0);
                flowsize.read(meta.migrateState, index);

                if (ishitVal == 0){
                    meta.progVal = meta.progVal + 1;
                    progress.write(0, meta.progVal);
                    ishit.write(index, 1);
                }

                clone3(CloneType.I2E, 300, {meta});
            }
        } else {
            mark_to_drop();
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            // add header for the I2E mirror packet
            if (hdr.ethernet.etherType == TYPE_IPV4) {
                // add migration header
                hdr.migration.push_front(1);
                hdr.migration[0].setValid();
                hdr.migration[0].state = meta.migrateState;
                hdr.migration[0].progVal = (bit<32>)meta.progVal;
                hdr.migration[0].next_type = 0;
                hdr.migration[0].protocol = (bit<32>)TCP_PROTOCOL;
                hdr.ipv4.protocol = MIGRATION_PROTOCOL;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.migration);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;