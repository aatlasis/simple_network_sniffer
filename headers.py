import struct
import ipaddress
import binascii
from textwrap import wrap
from iana_numbers import *

class Ethernet:
    def __init__(self, buff=None):
        header = struct.unpack('<6s6sH', buff)
        self.dstMac = binascii.hexlify(header[0])
        self.srcMac = binascii.hexlify(header[1])
        self.dstMac = ':'.join(wrap(self.dstMac.decode('utf-8'),2))
        self.srcMac = ':'.join(wrap(self.srcMac.decode('utf-8'),2))

        self.protocol_num = hex(header[2])
        # map protocol constants to their names
        self.protocol_map = {"0x8": "IPv4", "0xdd86": "IPv6", "0x68fe":"Spanning_Tree", "0x608":"ARP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            self.protocol = str(self.protocol_num)

class IPv4:
    def __init__(self, buff):
        header = struct.unpack('!BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = protocols 
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            self.protocol = str(self.protocol_num)

class IPv6:
    def __init__(self, buff):
        header = struct.unpack('!BBHHBB16s16s', buff)
        self.len = header[3]
        self.nh = header[4]
        self.hl = header[5]
        self.src = header[6]
        self.dst = header[7]

        # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = protocols 
        try:
            self.protocol = self.protocol_map[self.nh]
        except Exception as e:
            self.protocol = str(self.nh)

#RFC 6564
class IPv6EH:
    def __init__(self, buff):
        header = struct.unpack('!BB', buff)
        self.nh = header[0]
        self.len = header[1]

        # map protocol constants to their names
        self.protocol_map = protocols 
        try:
            self.protocol = self.protocol_map[self.nh]
        except Exception as e:
            self.protocol = str(self.nh)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('!BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

        # map ICMP type/code to their names
        self.icmp_map = icmp_type_code
        try:
            self.icmp = self.icmp_map[(self.type,self.code)]
        except Exception as e:
            self.icmp = "Type:"+str(self.type)+" : Code:"+str(self.code)

class ICMPv6:
    def __init__(self, buff):
        header = struct.unpack('!BBHBBH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]

        # map ICMP type/code to their names
        self.icmp_map = icmp6_type_code
        try:
            self.icmp = self.icmp_map[(self.type,self.code)]
        except Exception as e:
            self.icmp = "Type:"+str(self.type)+" : Code:"+str(self.code)

class UDP:
    def __init__(self, buff):
        header = struct.unpack('!HHHH', buff)
        self.sport = header[0]
        self.dport = header[1]
        self.len = header[2]
        self.sum = header[3]

class TCP:
    def __init__(self, buff):
        header = struct.unpack('!HHLLHHHH', buff)
        self.sport = header[0]
        self.dport = header[1]
        self.sequence = header[2]
        self.acknowledge = header[3]
        #self.len = header[4] >> 4
        flags = header[4] & 0x3F
        flags = "{0:{fill}6b}".format(flags, fill='0')
        self.flags=""
        if flags[0:1] == '1':
            self.flags=self.flags+'U'
        if flags[1:2] == '1':
            self.flags=self.flags+'A'
        if flags[2:3] == '1':
            self.flags=self.flags+'P'
        if flags[3:4] == '1':
            self.flags=self.flags+'R'
        if flags[4:5] == '1':
            self.flags=self.flags+'S'
        if flags[5:6] == '1':
            self.flags=self.flags+'F'
