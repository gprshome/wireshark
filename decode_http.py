#-*-coding:utf-8-*-
import dpkt
http = open("http.pcap", "rb")
packets = dpkt.pcap.Reader(http)
for ts, buf in packets:
    eth = dpkt.ethernet.Ethernet(buf)
    ip=eth.data
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        if tcp.dport == 80 and len(tcp.data) > 0:
            try:
                http_req = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            print("HTTP URI is ", http_req.uri)
            print("HTTP User-Agent is"+'【',http_req.headers['user-agent']+'】')
            print("HTTP Method is",http_req.method)
            print("HTTP connection value is",http_req.headers['connection'])
            print("HTTP host is",http_req.headers['host'])
            print("HTTP Accept is",http_req.headers['accept'])
            print("HTTP accept-encoding is", http_req.headers['accept-encoding'])
            print("HTTP accept-language is", http_req.headers['accept-language'])
            print('\n')
            '''
          #print all http request all content.
          for header in http_req.headers.keys():
              print(header, http_req.headers[header])
            '''

