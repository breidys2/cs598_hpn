#!/usr/bin/env python3

import re

from scapy.all import (
    Ether,
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    ByteField,
    bind_layers,
    srp1
)


class TM(Packet):
    name = "TM"
    """
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("op", "+", length=1),
                    IntField("operand_a", 0),
                    IntField("operand_b", 0),
                    IntField("result", 0xDEADBABE)]
    """
    fields_desc = [ ByteField("state", 0),
                    ByteField("head_location", 0),
                    ByteField("f0", 255),
                    ByteField("f1", 255),
                    ByteField("f2", 255),
                    ByteField("f3", 255),
                    ByteField("f4", 255),
                    ByteField("f5", 255),
                    ByteField("f6", 255),
                    ByteField("f7", 255),
                    ByteField("f8", 255),
                    ByteField("f9", 255),
                    ByteField("f10", 255),
                    ByteField("f11", 255),
                    ByteField("f12", 255),
                    ByteField("f13", 255),
                    ByteField("f14", 255),
                    ByteField("f15", 255),
                    ByteField("f16", 255),
                    ByteField("f17", 255),
                    ByteField("f18", 255),
                    ByteField("f19", 255),
                    ByteField("f20", 255)]

bind_layers(Ether, TM, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def num_parser(s, i, ts):
    pattern = "^\s*([0-9]+)\s*"
    match = re.match(pattern,s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise NumParseError('Expected number literal.')


def op_parser(s, i, ts):
    pattern = "^\s*([-+&|^])\s*"
    match = re.match(pattern,s[i:])
    if match:
        ts.append(Token('num', match.group(1)))
        return i + match.end(), ts
    raise NumParseError("Expected binary operator '-', '+', '&', '|', or '^'.")


def make_seq(p1, p2):
    def parse(s, i, ts):
        i,ts2 = p1(s,i,ts)
        return p2(s,i,ts2)
    return parse

def get_str(in_field):
    if in_field == 0: return "0"
    elif in_field == 1: return "1"
    elif in_field == 2: return "x"
    elif in_field == 3: return "s"
    elif in_field == 255: return "_"
    return "?"


def main():

    p = make_seq(num_parser, make_seq(op_parser,num_parser))
    s = ''
    iface = 'eth0'

    while True:
        s = input('> ')
        if s == "quit":
            break
        print(s)
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / TM()
            pkt = pkt/' '

            pkt.show()
            resp = srp1(pkt, iface=iface, timeout=2, verbose=False)
            if resp:
                tm=resp[TM]
                if tm:
                    out_str = ""
                    out_str += get_str(tm.f0)
                    out_str += get_str(tm.f1)
                    out_str += get_str(tm.f2)
                    out_str += get_str(tm.f3)
                    out_str += get_str(tm.f4)
                    out_str += get_str(tm.f5)
                    out_str += get_str(tm.f6)
                    out_str += get_str(tm.f7)
                    out_str += get_str(tm.f8)
                    out_str += get_str(tm.f9)
                    out_str += get_str(tm.f10)
                    out_str += get_str(tm.f11)
                    out_str += get_str(tm.f12)
                    out_str += get_str(tm.f13)
                    out_str += get_str(tm.f14)
                    out_str += get_str(tm.f15)
                    out_str += get_str(tm.f16)
                    out_str += get_str(tm.f17)
                    out_str += get_str(tm.f18)
                    out_str += get_str(tm.f19)
                    out_str += get_str(tm.f20)
                    out_str += "\n"
                    print(tm.head_location)
                    for j in range(tm.head_location):
                        out_str += " "
                    out_str += "^\n"
                    out_str += "State: " + str(tm.state)
                    print(out_str)
                else:
                    print("cannot find TM header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
