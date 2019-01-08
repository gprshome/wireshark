分享几个源码，通过DPKT来操作wireshark抓到的pcap包。
主要包括：
- get_ip_basic_info.py  ：获取pcap包每个IP包的包头基本信息。包括源地址、目的地址。源MAC、目的MAC、TTL等。
- get_new_pcap.py       : 读取pcap包，如果源IP是1.1.1.1，则把源IP修改为127.0.0.1，目的IP修改为127.0.0.2。并且生成一个新的包，叫test1.pcap
- decode_http.py        ：解码HTTP协议的包，读取HTTP请求中的基本信息。如host、uri、版本号、user-agent等。


欢迎关注51学通信
网站： www.51xuetongxin.com
公众号：51学通信
站长爱卫生微信：gprshome201101
