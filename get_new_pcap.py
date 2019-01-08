import dpkt
import socket
import time
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        return False
old = open("test.pcap","rb")
packets = dpkt.pcap.Reader(old)
new = open("test1.pcap","wb")
writer = dpkt.pcap.Writer(new)
for ts,buf in packets:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:  #过滤掉非IP包
        continue
    if inet_to_str(eth.data.src) == '1.1.1.1':
        eth.data.src = socket.inet_pton(socket.AF_INET, "127.0.0.1")
        eth.data.dst = socket.inet_pton(socket.AF_INET, "127.0.0.2")
    writer.writepkt(eth,ts=ts)
new.flush()
new.close()