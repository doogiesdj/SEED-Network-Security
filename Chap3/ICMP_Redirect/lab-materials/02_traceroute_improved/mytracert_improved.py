#!/usr/bin/env python3
from scapy.all import *

target = "192.168.60.5"
max_hops = 20

print("Improved Traceroute (ICMP Type Check + Stop on Destination)")
print("-----------------------------------------------------------")

for ttl in range(1, max_hops + 1):
    pkt = IP(dst=target, ttl=ttl) / ICMP()
    reply = sr1(pkt, timeout=2, verbose=0)

    if reply is None:
        print(f"{ttl}: *")
        continue

    # ICMP layer might be nested; Scapy exposes type via reply.type for ICMP packets
    # Type 11: Time Exceeded (router hop)
    if reply.type == 11:
        print(f"{ttl}: {reply.src} (Time Exceeded)")

    # Type 0: Echo Reply (destination reached)
    elif reply.type == 0:
        print(f"{ttl}: {reply.src} (Destination Reached)")
        break

    # Other ICMP types (e.g., Destination Unreachable)
    else:
        print(f"{ttl}: {reply.src} (ICMP type={reply.type})")
        break
