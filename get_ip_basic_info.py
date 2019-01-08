import dpkt
import socket
import time
from dpkt.compat import compat_ord
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        return False
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)
old = open("http.pcap", "rb")
packets = dpkt.pcap.Reader(old)
for ts, buf in packets:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:  # 过滤掉非IP包
        continue
    print(inet_to_str(eth.data.src))  #源IP
    print(inet_to_str(eth.data.dst))  #目的IP
    print(eth.data.len)  #IP头的总长度
    print(eth.data.ttl)  #TTL值
    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(eth.data.off & dpkt.ip.IP_DF)
    more_fragments = bool(eth.data.off & dpkt.ip.IP_MF)
    fragment_offset = eth.data.off & dpkt.ip.IP_OFFMASK
    print(do_not_fragment)  #DF flag
    print(more_fragments)   #MF flag
    print(fragment_offset)  #offset值
    print(mac_addr(eth.src)) #输出源MAC
    print(mac_addr(eth.dst)) #输出目的MAC
    print(eth.data.data.sport) #输出源端口号
    print(eth.data.data.dport) #输出目的端口号