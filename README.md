# simple network sniffer

Simple network sniffer; 
* It captures layer 3 - layer 4 traffic and provides a summary (protocol, ports, icmp types/codes, etc,)
* It optionally provides layer 2 and layer 5 (applicastion layer) info. 
* It supports both IPv4 and IPv6 (including IPv6 Extension headers)

## Requirements
* Python 3
* ipaddress python module

## Parameters
1. positional arguments:
  interface             The network interface to use for scanning

2. options:
  -h, --help            show this help message and exit
  -w WRITE, --write WRITE
                        The file to write the captured traffic
  -t TIMEOUT, --timeout TIMEOUT
                        The timeout (in sec) to sniff
  -l2, --layer2         Print also Layer 2 information
  -l5, --layer5         Layer 5 information will be saved in a file (must be combined with -w option). Layer 5 info is not
                        "printed" in tty for brevity reasons
  -4, --IPv4            IPv4 _only_ (default: both)
  -6, --IPv6            IPv6 _only_ (default: both)


