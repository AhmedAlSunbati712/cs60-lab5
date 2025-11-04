#!/usr/bin/env python3


# Author: Felipe Pavanelli
# Date: 11/03/2025
# Class: CS60 - Computer Networks
# port_scan.py - takes in a host IP Address and a range of port numbers. Checks which ports are open for TCP connection for given host


import sys
from scapy.all import IP, TCP, sr, conf, RandShort


#===================PARSE PORTS=========================#
# takes in ports string specification and returns sorted list of port numbers
# x-y: all ports between x and y, inclusive
# ,z: add port z to list
# LLM: coded with chatGPT
def parse_ports(spec: str):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


#===================PARSE PORTS=========================#
# takes in Host IP and port number specification
# prints out open ports for TCP connections for given host
# LLM citation: used ChatGPT to assist in parsing out packet reply
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 port_scan.py <ip> <portspec>")
        print("Example: python3 port_scan.py 192.168.60.5 1-1024,8080")
        sys.exit(1)

    ip = sys.argv[1]
    ports = parse_ports(sys.argv[2])
    if not ports:
        print("No valid ports parsed", file=sys.stderr)
        sys.exit(2)

    conf.verb = 0

    pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=ports, flags="S")
    ans, _ = sr(pkt, timeout=1, retry=0)

    open_ports = set()
    for _, r in ans:
        if r.haslayer(TCP):
            flags = int(r[TCP].flags)
            if (flags & 0x12) == 0x12:  # SYN-ACK
                open_ports.add(int(r[TCP].sport))

    for p in sorted(open_ports):
        print(p)

if __name__ == "__main__":
    main()