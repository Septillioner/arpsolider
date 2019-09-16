import json
from struct import unpack
from threading import Thread
from socket import inet_ntoa
from binascii import hexlify
SERVICES = json.loads(open("ports.json","rb").read())
def getProtocol(en):
    try:
        return {
            6:"tcp",
            17:"udp",
            1:"icmp"
        }[en]
    except KeyError:
        return "unknown"
def getService(port,type=6):
    try:
        return SERVICES["%s/%s"%(port,getProtocol(type))]
    except:
        return {u"name":u"unknown",u"description":u"Unknown service"}
class Packet:
    def __init__(self,src,dst,protocol,data=None,param=None,header=None):
        self.source=src
        self.destination=dst
        self.DataProtocol = protocol
        if(getProtocol(protocol) in ["tcp","udp"] and data):
            tf = unpack("!HH",data[0x24:0x28])
            self.source_port = tf[0]
            self.destination_port = tf[1]
            print("tcp/udp %s->%s"%(self.source_port,self.destination_port))
            self.Protocol = getService(protocol)
        self.data = data
        self.param = param
        self.header = header
from winpcapy import WinPcapUtils
class PCAPMonitor:
    ps="!BBHHHBBH4s4s"
    def __init__(self):
        self.packets = []
        self.capture = Thread(target=self.Capture_)
    def Capture_(self): WinPcapUtils.capture_on("*Ethernet*", self.Callback)
    def Capture(self):
        self.capture.start()
    def HexDump(self,chunk,name="Chunk"):
        hstr_ = []
        str_ = " ".join(map(hexlify,chunk)).upper()
        
        for i in xrange(len(chunk)):
            hstr_.append("%02X"%(i))
        hstr_ = " ".join(hstr_)
        print("%s%s"%(name,"-"*(int(len(chunk)*3-len(name)-1)) ))
        print(hstr_)
        print(str_)
    def Callback(self,win_pcap, param, header, pkt_data):
        if len(self.packets) > 1048576:
            self.packets.remove(self.packets[0])
        ipf = unpack(self.ps,pkt_data[0:0x14])
        self.HexDump(pkt_data[0:0x14],"IP Frame")
        protocol = ipf[6]
        print("%02X"%(protocol))
        src_ip = inet_ntoa(ipf[8])
        dst_ip = inet_ntoa(ipf[9])
        print src_ip,"->",dst_ip
        nc = Packet(src_ip,dst_ip,protocol,data=pkt_data,param=param,header=header)
        self.packets.append(nc)
pm = PCAPMonitor()
pm.Capture()