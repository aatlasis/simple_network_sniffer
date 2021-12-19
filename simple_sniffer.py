import sys
import os
import socket
import argparse
from iana_numbers import *
from headers import *
import time
import datetime

##TODO
## statistics - sumamry, FQDN resolution
##read pcap, save to pcap
##ICMPv6 main types/codes
##EH content
##intermediate header analysis for IPv4 too (eg when IKE/IPsec are used) 

class sniff:
    def __init__(self,values):
        self.write = values.write
        if self.write:
            try:
                self.f = open(values.write,'w')
            except OSError as e:
                print(e)
        self.host = values.interface 
        self.layer2 = values.layer2
        self.layer5 = values.layer5
        self.IPv4 = values.IPv4
        self.IPv6 = values.IPv6
        self.l2_length = 14 #Length of Ethernet header
        self.l4_offset = 0
        self.l4_header = None 
        try:
            sniffer = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
            sniffer.bind((self.host, 0))
            print('start sniffing address: ',self.host)
        except PermissionError as e:
            print("Please run as root!")
            exit(1)
        if  os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        try:

            t_end = time.time() + float(values.timeout)
            while time.time() < t_end:
                #print(sniffer.recvfrom(65565))
                self.raw_buffer = sniffer.recvfrom(65535)[0]
                date = f"{datetime.datetime.now()}"
                self.mac_header = Ethernet(self.raw_buffer[0:14])

                #### Layer 3 = IPv4 ###
                if self.mac_header.protocol == "IPv4" and (not self.IPv6):  
                    self.ip_header = IPv4(self.raw_buffer[self.l2_length:self.l2_length+20])
                    self.l3_length = self.ip_header.ihl * 4
                    self.l4_offset = self.l2_length+self.l3_length
                    self.l4_header = self.ip_header.protocol
                    if self.l4_header == "ICMP":
                        buf = self.raw_buffer[self.l4_offset:self.l4_offset+8]
                        icmp_header = ICMP(buf)
                        results = f"{self.ip_header.src_address} -> {self.ip_header.dst_address} {self.ip_header.len} {self.l4_header} {icmp_header.icmp}"
                        if self.layer2:
                            results = " ".join([f"{self.mac_header.srcMac} -> {self.mac_header.dstMac}",results])
                        print(results)
                        if self.layer5:
                            payload = self.raw_buffer[self.l4_offset+8:self.ip_header.len+self.l2_length]
                            results = " ".join([results,str(payload).strip("'b")])
                        if self.write:
                            print(results,file=self.f)

                    elif self.l4_header == "TCP" or self.l4_header == "UDP":
                        self.layer4_packet_analysis()

                #### Layer 3 = IPv6 ###
                elif self.mac_header.protocol == "IPv6" and (not self.IPv4):  
                    self.l3_length = 40
                    self.l4_offset = self.l2_length+self.l3_length
                    self.ip_header = IPv6(self.raw_buffer[self.l2_length:self.l2_length+self.l3_length])
                    next_header = self.ip_header.protocol
                    eh = next_header
                    while next_header != "TCP" and next_header != "UDP" and next_header != "ICMPv6":
                        buf = self.raw_buffer[self.l4_offset:self.l4_offset+2] 
                        ipv6eh = IPv6EH(buf)
                        if next_header == "Fragment":
                            next_header = ipv6eh.protocol
                            self.l4_offset = self.l4_offset + 8
                        else:
                            next_header = ipv6eh.protocol
                            self.l4_offset = self.l4_offset + (ipv6eh.len+1) * 8 
                        eh = eh + "," + next_header

                    self.l4_header = next_header
                    if self.l4_header == "ICMPv6":
                        buf = self.raw_buffer[self.l4_offset:self.l4_offset+8]
                        icmp_header = ICMPv6(buf)
                        results = f"{self.ip_header.src_address} -> {self.ip_header.dst_address} {self.ip_header.len} {eh} {icmp_header.icmp}"
                        if self.layer2:
                            results = " ".join([f"{self.mac_header.srcMac} -> {self.mac_header.dstMac}",results])
                        print(results)
                        if self.layer5:
                            payload = self.raw_buffer[self.l4_offset+8:self.ip_header.len+self.l2_length]
                            results = " ".join([results,str(payload).strip("'b")])
                        if self.write:
                            print(results,file=self.f)
                    elif self.l4_header == "TCP" or self.l4_header == "UDP":
                        self.layer4_packet_analysis()

                ### Other Protocols ###
                #elif self.layer2 and (not self.IPv4) and (not self.IPv6):
                #    print(self.mac_header.protocol)
            if self.write:
                self.f.close()
        except KeyboardInterrupt:
            if  os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            if self.write:
                self.f.close()
            sys.exit()

    def layer4_packet_analysis(self):
        if self.l4_header == "TCP":
            buf = self.raw_buffer[self.l4_offset:self.l4_offset+20]
            tcp_header = TCP(buf)
            results = f'{self.ip_header.src_address} -> {self.ip_header.dst_address} {self.ip_header.len} {self.l4_header} {tcp_header.sport} -> {tcp_header.dport} {tcp_header.flags}'
            if self.layer2:
                results = " ".join([f"{self.mac_header.srcMac} -> {self.mac_header.dstMac}",results])
            print(results)
            if self.layer5:
                payload = self.raw_buffer[self.l4_offset+8:self.ip_header.len+self.l2_length]
                results = " ".join([results,str(payload).strip("'b")])
            if self.write:
                print(results,file=self.f)
        elif self.l4_header == "UDP":
            buf = self.raw_buffer[self.l4_offset:self.l4_offset+8]
            udp_header = UDP(buf)
            results = f'{self.ip_header.src_address} -> {self.ip_header.dst_address} {self.ip_header.len} {self.l4_header} {udp_header.sport} -> {udp_header.dport}'
            if self.layer2:
                results = " ".join([f"{self.mac_header.srcMac} -> {self.mac_header.dstMac}",results])
            print(results)
            if self.layer5:
                payload = self.raw_buffer[self.l4_offset+8:self.ip_header.len+self.l2_length]
                results = " ".join([results,str(payload).strip("'b")])
            if self.write:
                print(results,file=self.f)
        else:
            results = f'{self.ip_header.src_address} -> {self.ip_header.dst_address} {self.ip_header.len} {self.l4_header}'
            if self.layer2:
                results = " ".join([f"{self.mac_header.srcMac} -> {self.mac_header.dstMac}",results])
            print(results)
            if self.write:
                print(results,file=self.f)

def main(): 
    parser = argparse.ArgumentParser(description='A simple network sniffer')
    parser.add_argument('interface', help='The network interface to use for scanning')
    parser.add_argument('-w', '--write', required=False, default=None, help='The file to write the captured traffic')
    parser.add_argument('-t', '--timeout', required=False, default=10.0, help='The timeout (in sec) to sniff')
    parser.add_argument('-l2', '--layer2', action="store_true", required=False, default=False, help='Print also Layer 2 information')
    parser.add_argument('-l5', '--layer5', action="store_true", required=False, default=False, help='Layer 5 information will be saved in a file (must be combined with -w option). Layer 5 info is not "printed" in tty for brevity reasons')
    parser.add_argument('-4', '--IPv4', action="store_true", required=False, default=False, help='IPv4 _only_ (default: both)')
    parser.add_argument('-6', '--IPv6', action="store_true", required=False, default=False, help='IPv6 _only_ (default: both)')
    values = parser.parse_args()
        
    mysniffer = sniff(values)

if __name__ == '__main__':
    main()
