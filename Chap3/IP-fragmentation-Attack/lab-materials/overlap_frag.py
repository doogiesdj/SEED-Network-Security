from scapy.all import *
import time

dst = "10.9.0.5"
ID  = 3333

# base payload: 112 bytes total
data_base = b"A"*112

# fragment 1: offset 0, MF=1
# carry UDP header + first 72 bytes => 80 bytes IP payload (8-byte aligned)
data1 = b"A"*72
udp_len = 8 + 112
udp = UDP(sport=4444, dport=9090, len=udp_len, chksum=0)
frag1 = IP(dst=dst, id=ID, flags="MF", frag=0)/udp/data1

# fragment 2 (normal continuation would start at offset 80 bytes => frag=10)
# BUT we will OVERLAP by starting earlier: offset 72 bytes (frag=9)
# frag=9 means 9*8=72 bytes into IP payload -> overlaps last 8 bytes of fragment 1 payload
overlap_data = b"B"*40  # this will overwrite some bytes if OS uses "last wins"
frag2 = IP(dst=dst, id=ID, flags=0, frag=9, proto=17)/overlap_data

send(frag1, verbose=0)
time.sleep(0.2)
send(frag2, verbose=0)

print("Overlapping fragments sent")
