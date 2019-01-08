#-*-coding:utf-8-*-
import dpkt
import datetime
sip = open("sip.pcap", "rb")
packets = dpkt.pcap.Reader(sip)
for ts, buf in packets:
    eth = dpkt.ethernet.Ethernet(buf)
    ip=eth.data
    if isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        if udp.dport == 5060 or udp.sport == 5060 and len(udp.data) >= 0:
            try:
                sip_req = dpkt.sip.Request(udp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            try:
                print('Timestamp is: ', str(datetime.datetime.utcfromtimestamp(ts)))
                print("SIP URI is ", sip_req.uri)
                print("SIP From is"+'【',sip_req.headers['from']+'】')
                print("SIP To is" + '【', sip_req.headers['to'] + '】')
                print("SIP Method is",sip_req.method)
                print("SIP via is",sip_req.headers['via'])
                print("SIP Cseq is",sip_req.headers['cseq'])
                print("SIP Contact is", sip_req.headers['contact'])
                print("SIP Call-ID is", sip_req.headers['call-id'])
                print('*'*60)
            except:
                continue


        '''
          #print all http request all content.
            for header in sip_req.headers.keys():
                print(header, sip_req.headers[header])
            print('\n')
       '''
        '''
            #也可以通过字典的方法来取出整个SIP Header
            a=dict(sip_req.headers)
            for kv in a.items():
                print(kv)
            print('\n')
       '''


