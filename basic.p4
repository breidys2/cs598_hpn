/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */

/*
 * Standard ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * Custom Turing Machine Header
 */
header tm_t {
    bit<8> tm_state;
    bit<8> head_location;
    bit<8> f0;
    bit<8> f1;
    bit<8> f2;
    bit<8> f3;
    bit<8> f4;
    bit<8> f5;
    bit<8> f6;
    bit<8> f7;
    bit<8> f8;
    bit<8> f9;
}

const bit<16> TM_ETYPE = 0x1234;

/*
 * All headers, used in the program needs to be assembed into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    tm_t     tm;
}

/*
 * All metadata, globally used in the program, also  needs to be assembed
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TM_ETYPE : parse_tm;
            default      : accept;
        }
    }

    state parse_tm {
        packet.extract(hdr.tm);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action print_0() {
        hdr.tm.f0 = 0;
        hdr.tm.f1 = 1;
        hdr.tm.head_location = hdr.tm.head_location + 2;
    }
    action print_2() {
        hdr.tm.f2 = 0;
        hdr.tm.f3 = 1;
        hdr.tm.head_location = hdr.tm.head_location + 2;
    }
    action print_4() {
        hdr.tm.f4 = 0;
        hdr.tm.f5 = 1;
        hdr.tm.head_location = hdr.tm.head_location + 2;
    }
    action print_6() {
        hdr.tm.f6 = 0;
        hdr.tm.f7 = 1;
        hdr.tm.head_location = hdr.tm.head_location + 2;
    }
    action print_8() {
        hdr.tm.f8 = 0;
        hdr.tm.f9 = 1;
        hdr.tm.head_location = hdr.tm.head_location + 2;
    }
    action send_back() {
        bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        //standard_metadata.egress_spec = standard_metadata.ingress_port;
        standard_metadata.egress_spec =1;
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }
    table return_ans {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            send_back();
        }
        const entries = {
            10: send_back();
        }
    }

    table process {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            print_0;
            print_2;
            print_4;
            print_6;
            print_8;
            send_back();
        }
        const entries = {
            0: print_0();
            2: print_2();
            4: print_4();
            6: print_6();
            8: print_8();
        }
    }


    apply {
        if (hdr.tm.isValid()) {
            process.apply();
            return_ans.apply();
        } else {
            operation_drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action recirc() {
        recirculate_preserving_field_list(0);
    }
    table recirculate_packet {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            recirc();
        }
        const entries = {
            2: recirc();
            4: recirc();
            6: recirc();
            8: recirc();
        }
    }
    apply { 
        if (hdr.tm.isValid()) {
            recirculate_packet.apply();
        }
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tm);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
