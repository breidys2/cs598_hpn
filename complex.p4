/* -*- P4_16 -*- */

/*
 * P4 Calculator
 *
 * This program implements a simple protocol. It can be carried over Ethernet
 * (Ethertype 0x1234).
 *
 * The device receives a packet, performs the requested operation, fills in the
 * result and sends the packet back out of the same port it came in on, while
 * swapping the source and destination addresses.
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped
 */

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
    bit<8> f10;
    bit<8> f11;
    bit<8> f12;
    bit<8> f13;
    bit<8> f14;
    bit<8> f15;
    bit<8> f16;
    bit<8> f17;
    bit<8> f18;
    bit<8> f19;
    bit<8> f20;
}

#define START 3
#define X 2
#define BLANK 255

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

    action operation_drop() {
        mark_to_drop(standard_metadata);
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
    table return_ans {
        key = {
            hdr.tm.tm_state        : exact;
        }
        actions = {
            send_back();
        }
        const entries = {
            //4: send_back();
            5: send_back();
        }
    }
    action init_a() {
        hdr.tm.f0 = START;
        hdr.tm.head_location = hdr.tm.head_location + 1;
        hdr.tm.f1 = START;
        hdr.tm.head_location = hdr.tm.head_location + 1;
        hdr.tm.f2 = 0;
        hdr.tm.head_location = hdr.tm.head_location + 2;
        hdr.tm.f4 = 0;
        hdr.tm.head_location = hdr.tm.head_location - 2;
        hdr.tm.tm_state = 1;
    }
    table process_init {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            init_a();
        }
        const default_action = init_a();
    }

    action process_ba() {
        bit<8> cur_val;
        if (hdr.tm.head_location == 0) cur_val = hdr.tm.f0;
        if (hdr.tm.head_location == 1) cur_val = hdr.tm.f1;
        if (hdr.tm.head_location == 2) cur_val = hdr.tm.f2;
        if (hdr.tm.head_location == 3) cur_val = hdr.tm.f3;
        if (hdr.tm.head_location == 4) cur_val = hdr.tm.f4;
        if (hdr.tm.head_location == 5) cur_val = hdr.tm.f5;
        if (hdr.tm.head_location == 6) cur_val = hdr.tm.f6;
        if (hdr.tm.head_location == 7) cur_val = hdr.tm.f7;
        if (hdr.tm.head_location == 8) cur_val = hdr.tm.f8;
        if (hdr.tm.head_location == 9) cur_val = hdr.tm.f9;
        if (hdr.tm.head_location == 10) cur_val = hdr.tm.f10;
        if (hdr.tm.head_location == 11) cur_val = hdr.tm.f11;
        if (hdr.tm.head_location == 12) cur_val = hdr.tm.f12;
        if (hdr.tm.head_location == 13) cur_val = hdr.tm.f13;
        if (hdr.tm.head_location == 14) cur_val = hdr.tm.f14;
        if (hdr.tm.head_location == 15) cur_val = hdr.tm.f15;
        if (hdr.tm.head_location == 16) cur_val = hdr.tm.f16;
        if (hdr.tm.head_location == 17) cur_val = hdr.tm.f17;
        if (hdr.tm.head_location == 18) cur_val = hdr.tm.f18;
        if (hdr.tm.head_location == 19) cur_val = hdr.tm.f19;
        if (hdr.tm.head_location == 20) cur_val = hdr.tm.f20;
        
        if (cur_val == 0) {
            hdr.tm.tm_state = 2;
        } else if (cur_val == 1) {
            hdr.tm.head_location = hdr.tm.head_location + 1;
            if (hdr.tm.head_location == 0) hdr.tm.f0 = X;
            if (hdr.tm.head_location == 1) hdr.tm.f1 = X;
            if (hdr.tm.head_location == 2) hdr.tm.f2 = X;
            if (hdr.tm.head_location == 3) hdr.tm.f3 = X;
            if (hdr.tm.head_location == 4) hdr.tm.f4 = X;
            if (hdr.tm.head_location == 5) hdr.tm.f5 = X;
            if (hdr.tm.head_location == 6) hdr.tm.f6 = X;
            if (hdr.tm.head_location == 7) hdr.tm.f7 = X;
            if (hdr.tm.head_location == 8) hdr.tm.f8 = X;
            if (hdr.tm.head_location == 9) hdr.tm.f9 = X;
            if (hdr.tm.head_location == 10) hdr.tm.f10 = X;
            if (hdr.tm.head_location == 11) hdr.tm.f11 = X;
            if (hdr.tm.head_location == 12) hdr.tm.f12 = X;
            if (hdr.tm.head_location == 13) hdr.tm.f13 = X;
            if (hdr.tm.head_location == 14) hdr.tm.f14 = X;
            if (hdr.tm.head_location == 15) hdr.tm.f15 = X;
            if (hdr.tm.head_location == 16) hdr.tm.f16 = X;
            if (hdr.tm.head_location == 17) hdr.tm.f17 = X;
            if (hdr.tm.head_location == 18) hdr.tm.f18 = X;
            if (hdr.tm.head_location == 19) hdr.tm.f19 = X;
            if (hdr.tm.head_location == 20) hdr.tm.f20 = X;
            hdr.tm.head_location = hdr.tm.head_location - 3;
        }
    }

    table process_b {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            process_ba();
        }
        const default_action = process_ba();
    }

    action process_ca() {
        bit<8> cur_val;
        if (hdr.tm.head_location == 0) cur_val = hdr.tm.f0;
        if (hdr.tm.head_location == 1) cur_val = hdr.tm.f1;
        if (hdr.tm.head_location == 2) cur_val = hdr.tm.f2;
        if (hdr.tm.head_location == 3) cur_val = hdr.tm.f3;
        if (hdr.tm.head_location == 4) cur_val = hdr.tm.f4;
        if (hdr.tm.head_location == 5) cur_val = hdr.tm.f5;
        if (hdr.tm.head_location == 6) cur_val = hdr.tm.f6;
        if (hdr.tm.head_location == 7) cur_val = hdr.tm.f7;
        if (hdr.tm.head_location == 8) cur_val = hdr.tm.f8;
        if (hdr.tm.head_location == 9) cur_val = hdr.tm.f9;
        if (hdr.tm.head_location == 10) cur_val = hdr.tm.f10;
        if (hdr.tm.head_location == 11) cur_val = hdr.tm.f11;
        if (hdr.tm.head_location == 12) cur_val = hdr.tm.f12;
        if (hdr.tm.head_location == 13) cur_val = hdr.tm.f13;
        if (hdr.tm.head_location == 14) cur_val = hdr.tm.f14;
        if (hdr.tm.head_location == 15) cur_val = hdr.tm.f15;
        if (hdr.tm.head_location == 16) cur_val = hdr.tm.f16;
        if (hdr.tm.head_location == 17) cur_val = hdr.tm.f17;
        if (hdr.tm.head_location == 18) cur_val = hdr.tm.f18;
        if (hdr.tm.head_location == 19) cur_val = hdr.tm.f19;
        if (hdr.tm.head_location == 20) cur_val = hdr.tm.f20;
        
        if (cur_val == 0 || cur_val == 1) {
            hdr.tm.tm_state = 2;
            hdr.tm.head_location = hdr.tm.head_location + 2;
        } else if (cur_val == BLANK) {
            if (hdr.tm.head_location == 0) hdr.tm.f0 = 1;
            if (hdr.tm.head_location == 1) hdr.tm.f1 = 1;
            if (hdr.tm.head_location == 2) hdr.tm.f2 = 1;
            if (hdr.tm.head_location == 3) hdr.tm.f3 = 1;
            if (hdr.tm.head_location == 4) hdr.tm.f4 = 1;
            if (hdr.tm.head_location == 5) hdr.tm.f5 = 1;
            if (hdr.tm.head_location == 6) hdr.tm.f6 = 1;
            if (hdr.tm.head_location == 7) hdr.tm.f7 = 1;
            if (hdr.tm.head_location == 8) hdr.tm.f8 = 1;
            if (hdr.tm.head_location == 9) hdr.tm.f9 = 1;
            if (hdr.tm.head_location == 10) hdr.tm.f10 = 1;
            if (hdr.tm.head_location == 11) hdr.tm.f11 = 1;
            if (hdr.tm.head_location == 12) hdr.tm.f12 = 1;
            if (hdr.tm.head_location == 13) hdr.tm.f13 = 1;
            if (hdr.tm.head_location == 14) hdr.tm.f14 = 1;
            if (hdr.tm.head_location == 15) hdr.tm.f15 = 1;
            if (hdr.tm.head_location == 16) hdr.tm.f16 = 1;
            if (hdr.tm.head_location == 17) hdr.tm.f17 = 1;
            if (hdr.tm.head_location == 18) hdr.tm.f18 = 1;
            if (hdr.tm.head_location == 19) hdr.tm.f19 = 1;
            if (hdr.tm.head_location == 20) hdr.tm.f20 = 1;
            hdr.tm.head_location = hdr.tm.head_location - 1;
            hdr.tm.tm_state = 3;
        }
        if (hdr.tm.tm_state == 3 && hdr.tm.head_location == 19) {
            //Goto end
            hdr.tm.tm_state = 5;
        }
    }
    table process_c {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            process_ca();
        }
        const default_action = process_ca();
    }
    action process_da() {
        bit<8> cur_val;
        if (hdr.tm.head_location == 0) cur_val = hdr.tm.f0;
        if (hdr.tm.head_location == 1) cur_val = hdr.tm.f1;
        if (hdr.tm.head_location == 2) cur_val = hdr.tm.f2;
        if (hdr.tm.head_location == 3) cur_val = hdr.tm.f3;
        if (hdr.tm.head_location == 4) cur_val = hdr.tm.f4;
        if (hdr.tm.head_location == 5) cur_val = hdr.tm.f5;
        if (hdr.tm.head_location == 6) cur_val = hdr.tm.f6;
        if (hdr.tm.head_location == 7) cur_val = hdr.tm.f7;
        if (hdr.tm.head_location == 8) cur_val = hdr.tm.f8;
        if (hdr.tm.head_location == 9) cur_val = hdr.tm.f9;
        if (hdr.tm.head_location == 10) cur_val = hdr.tm.f10;
        if (hdr.tm.head_location == 11) cur_val = hdr.tm.f11;
        if (hdr.tm.head_location == 12) cur_val = hdr.tm.f12;
        if (hdr.tm.head_location == 13) cur_val = hdr.tm.f13;
        if (hdr.tm.head_location == 14) cur_val = hdr.tm.f14;
        if (hdr.tm.head_location == 15) cur_val = hdr.tm.f15;
        if (hdr.tm.head_location == 16) cur_val = hdr.tm.f16;
        if (hdr.tm.head_location == 17) cur_val = hdr.tm.f17;
        if (hdr.tm.head_location == 18) cur_val = hdr.tm.f18;
        if (hdr.tm.head_location == 19) cur_val = hdr.tm.f19;
        if (hdr.tm.head_location == 20) cur_val = hdr.tm.f20;
        if (cur_val == X) {
            if (hdr.tm.head_location == 0) hdr.tm.f0 = BLANK;
            if (hdr.tm.head_location == 1) hdr.tm.f1 = BLANK;
            if (hdr.tm.head_location == 2) hdr.tm.f2 = BLANK;
            if (hdr.tm.head_location == 3) hdr.tm.f3 = BLANK;
            if (hdr.tm.head_location == 4) hdr.tm.f4 = BLANK;
            if (hdr.tm.head_location == 5) hdr.tm.f5 = BLANK;
            if (hdr.tm.head_location == 6) hdr.tm.f6 = BLANK;
            if (hdr.tm.head_location == 7) hdr.tm.f7 = BLANK;
            if (hdr.tm.head_location == 8) hdr.tm.f8 = BLANK;
            if (hdr.tm.head_location == 9) hdr.tm.f9 = BLANK;
            if (hdr.tm.head_location == 10) hdr.tm.f10 = BLANK;
            if (hdr.tm.head_location == 11) hdr.tm.f11 = BLANK;
            if (hdr.tm.head_location == 12) hdr.tm.f12 = BLANK;
            if (hdr.tm.head_location == 13) hdr.tm.f13 = BLANK;
            if (hdr.tm.head_location == 14) hdr.tm.f14 = BLANK;
            if (hdr.tm.head_location == 15) hdr.tm.f15 = BLANK;
            if (hdr.tm.head_location == 16) hdr.tm.f16 = BLANK;
            if (hdr.tm.head_location == 17) hdr.tm.f17 = BLANK;
            if (hdr.tm.head_location == 18) hdr.tm.f18 = BLANK;
            if (hdr.tm.head_location == 19) hdr.tm.f19 = BLANK;
            if (hdr.tm.head_location == 20) hdr.tm.f20 = BLANK;
            hdr.tm.head_location = hdr.tm.head_location + 1;
            hdr.tm.tm_state = 2;
        } else if (cur_val == START) {
            hdr.tm.head_location = hdr.tm.head_location + 1;
            hdr.tm.tm_state = 4;
        } else if (cur_val == BLANK) {
            hdr.tm.head_location = hdr.tm.head_location - 2;
        }
    }
    table process_d {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            process_da();
        }
        const default_action = process_da();
    }
    action process_ea() {
        bit<8> cur_val;
        if (hdr.tm.head_location == 0) cur_val = hdr.tm.f0;
        if (hdr.tm.head_location == 1) cur_val = hdr.tm.f1;
        if (hdr.tm.head_location == 2) cur_val = hdr.tm.f2;
        if (hdr.tm.head_location == 3) cur_val = hdr.tm.f3;
        if (hdr.tm.head_location == 4) cur_val = hdr.tm.f4;
        if (hdr.tm.head_location == 5) cur_val = hdr.tm.f5;
        if (hdr.tm.head_location == 6) cur_val = hdr.tm.f6;
        if (hdr.tm.head_location == 7) cur_val = hdr.tm.f7;
        if (hdr.tm.head_location == 8) cur_val = hdr.tm.f8;
        if (hdr.tm.head_location == 9) cur_val = hdr.tm.f9;
        if (hdr.tm.head_location == 10) cur_val = hdr.tm.f10;
        if (hdr.tm.head_location == 11) cur_val = hdr.tm.f11;
        if (hdr.tm.head_location == 12) cur_val = hdr.tm.f12;
        if (hdr.tm.head_location == 13) cur_val = hdr.tm.f13;
        if (hdr.tm.head_location == 14) cur_val = hdr.tm.f14;
        if (hdr.tm.head_location == 15) cur_val = hdr.tm.f15;
        if (hdr.tm.head_location == 16) cur_val = hdr.tm.f16;
        if (hdr.tm.head_location == 17) cur_val = hdr.tm.f17;
        if (hdr.tm.head_location == 18) cur_val = hdr.tm.f18;
        if (hdr.tm.head_location == 19) cur_val = hdr.tm.f19;
        if (hdr.tm.head_location == 20) cur_val = hdr.tm.f20;
        if (cur_val != BLANK) {
            hdr.tm.head_location = hdr.tm.head_location + 2;
        } else {
            if (hdr.tm.head_location == 0) hdr.tm.f0 = 0;
            if (hdr.tm.head_location == 1) hdr.tm.f1 = 0;
            if (hdr.tm.head_location == 2) hdr.tm.f2 = 0;
            if (hdr.tm.head_location == 3) hdr.tm.f3 = 0;
            if (hdr.tm.head_location == 4) hdr.tm.f4 = 0;
            if (hdr.tm.head_location == 5) hdr.tm.f5 = 0;
            if (hdr.tm.head_location == 6) hdr.tm.f6 = 0;
            if (hdr.tm.head_location == 7) hdr.tm.f7 = 0;
            if (hdr.tm.head_location == 8) hdr.tm.f8 = 0;
            if (hdr.tm.head_location == 9) hdr.tm.f9 = 0;
            if (hdr.tm.head_location == 10) hdr.tm.f10 = 0;
            if (hdr.tm.head_location == 11) hdr.tm.f11 = 0;
            if (hdr.tm.head_location == 12) hdr.tm.f12 = 0;
            if (hdr.tm.head_location == 13) hdr.tm.f13 = 0;
            if (hdr.tm.head_location == 14) hdr.tm.f14 = 0;
            if (hdr.tm.head_location == 15) hdr.tm.f15 = 0;
            if (hdr.tm.head_location == 16) hdr.tm.f16 = 0;
            if (hdr.tm.head_location == 17) hdr.tm.f17 = 0;
            if (hdr.tm.head_location == 18) hdr.tm.f18 = 0;
            if (hdr.tm.head_location == 19) hdr.tm.f19 = 0;
            if (hdr.tm.head_location == 20) hdr.tm.f20 = 0;
            hdr.tm.head_location = hdr.tm.head_location - 2;
            hdr.tm.tm_state = 1;
        } 
    }

    table process_e {
        key = {
            hdr.tm.head_location        : exact;
        }
        actions = {
            process_ea();
        }
        const default_action = process_ea();
    }


    apply {
        if (hdr.tm.isValid()) {
            if (hdr.tm.tm_state == 0) {
                //Init state
                process_init.apply();
            }
            else if (hdr.tm.tm_state == 1) {
                process_b.apply();
            }
            else if (hdr.tm.tm_state == 2) {
                process_c.apply();
            }
            else if (hdr.tm.tm_state == 3) {
                process_d.apply();
            }
            else if (hdr.tm.tm_state == 4) {
                process_e.apply();
            }
            log_msg("head_loc = {}, state = {}", {hdr.tm.head_location, hdr.tm.tm_state});
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
            hdr.tm.tm_state        : exact;
        }
        actions = {
            recirc();
        }
        const entries = {
            0: recirc();
            1: recirc();
            2: recirc();
            3: recirc();
            4: recirc();
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
