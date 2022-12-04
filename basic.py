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
                    ByteField("f0", 3),
                    ByteField("f1", 3),
                    ByteField("f2", 3),
                    ByteField("f3", 3),
                    ByteField("f4", 3),
                    ByteField("f5", 3),
                    ByteField("f6", 3),
                    ByteField("f7", 3),
                    ByteField("f8", 3),
                    ByteField("f9", 3),
                    ByteField("padding", 3)]

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
                    out_str += str(tm.f0)
                    out_str += str(tm.f1)
                    out_str += str(tm.f2)
                    out_str += str(tm.f3)
                    out_str += str(tm.f4)
                    out_str += str(tm.f5)
                    out_str += str(tm.f6)
                    out_str += str(tm.f7)
                    out_str += str(tm.f8)
                    out_str += str(tm.f9)
                    print(out_str)
                else:
                    print("cannot find TM header in the packet")
            else:
                print("Didn't receive response")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
