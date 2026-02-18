from scapy.all import *

dst = "10.9.0.5"
ID  = 2222

data1 = b"A"*72     # first fragment data (72B)
data2 = b"B"*40     # second fragment data (40B)
udp_len = 8 + len(data1) + len(data2)   # full UDP length

# 1st fragment: UDP header + first data
udp = UDP(sport=4444, dport=9090, len=udp_len, chksum=0)
frag1 = IP(dst=dst, id=ID, flags="MF", frag=0)/udp/data1

# 2nd fragment: MUST keep proto=17, offset = 80 bytes => frag=10
frag2 = IP(dst=dst, id=ID, flags=0, frag=10, proto=17)/data2

send(frag1, verbose=0)
send(frag2, verbose=0)

print("Manual fragments sent OK")
