#!/usr/bin/env python3
from scapy.all import *

target = "192.168.60.5"

print("Basic Traceroute (No ICMP Type Check)")
print("--------------------------------------")

for ttl in range(1, 10):
    pkt = IP(dst=target, ttl=ttl)/ICMP()
    reply = sr1(pkt, timeout=2, verbose=0)

    if reply is None:
        print(f"{ttl}: *")
    else:
        print(f"{ttl}: {reply.src}")
