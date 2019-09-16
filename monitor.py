import json
from struct import unpack
from threading import Thread
from binascii import hexlify
from socket import inet_ntoa
import time
def inet_ntom(mac):
    return ":".join(map(hexlify,mac))
SERVICES = json.loads(open("ports.json","rb").read())
OUI = [[j.rstrip() for j in i.split("\t")] for i in open("ieee-oui.lst","rb").readlines()]
def getProtocol(en):
    try:
        return {
            6:"tcp",
            17:"udp",
            1:"icmp"
        }[en]
    except KeyError:
        return "unknown"
def OuiLookup(mac):
    global OUI
    mac_ = "".join(mac.split(":")[0:3]).lower() if mac.find(":") > -1 else mac.lower()
    try:
        for line in OUI:
            if(mac_.startswith(line[0].lower())):
                return "%s_%s"%(line[1],":".join(mac.split(":")[3:6]) if mac.find(":") > -1 else ":".join(map(mac)[3:6]))
    except:
        return mac
    return mac
def getService(port,type=6):
    try:
        return SERVICES["%s/%s"%(port,getProtocol(type))]
    except:
        return {u"name":u"unknown",u"description":u"Unknown service"}
class Packet:
    ptcp = "!HHLLBBHHH"
    pudp = "!HHHH"
    def __init__(self,src,dst,protocol,ipf,iph,data,param=None,header=None):
        self.source=src
        self.destination=dst
        self.DataProtocol = protocol
        self.iph = iph
        _f = (ipf[0] & 0xF)*4
        self.ttl = ipf[5]
        self.source_port=0
        self.destination_port=0
        self.protocol = protocol
        self.db=None
        self.Protocol = getService("")
        if(getProtocol(protocol) == "tcp"):
            self.af = data[14+_f:_f+0x22]
            self.ph = unpack(self.ptcp,self.af)
            doff_reserved = self.ph[4]
            tcph_length = doff_reserved & 4
            h_size = 0x14+_f + tcph_length * 4
            self.db = data[h_size:]
            self.source_port = self.ph[0]
            self.destination_port = self.ph[1]
            self.Protocol = getService(self.destination_port if self.destination_port < self.source_port else self.source_port,protocol)
            #print("tcp %s->%s"%(self.source_port,self.destination_port))
        elif(getProtocol(protocol) == "udp"):
            self.af = data[14+_f:_f+0x1C]
            self.ph = unpack(self.pudp,data[0x24:0x2c])
            h_size = 0x14+_f+ 8
            self.db = data[h_size:]
            self.source_port = self.ph[0]
            self.destination_port = self.ph[1]
            self.Protocol = getService(self.destination_port if self.destination_port < self.source_port else self.source_port,protocol)
            #print("udp %s->%s"%(self.source_port,self.destination_port))
        self.data = data
        if(not self.db):self.db=self.data
        self.param = param
        self.header = header
    
from winpcapy import WinPcapUtils
class PCAPMonitor:
    ps="!BBHHHBBH4s4s"
    ppkt = "!6s6sH"
    def __init__(self):
        self.packets = []
        self._iter = 0
        self.capture = Thread(target=self.Capture_)
    def Capture_(self): WinPcapUtils.capture_on("*Ethernet*", self.Callback)
    def Capture(self):
        self.capture.start()
    def HexDump(self,chunk,name="Chunk"):
        hstr_ = []
        hstr2_ = []
        str_ = "  ".join(map(hexlify,chunk)).upper()
        for i in xrange(len(chunk)):
            hstr_.append("%02X"%(i))
            hstr2_.append("%03d"%(ord(chunk[i])))
        hstr_ = "  ".join(hstr_)
        hstr2_ = " ".join(hstr2_)
        print("%s%s"%(name,"-"*(int(len(chunk)*4-len(name)-1)) ))
        print(hstr_)
        print(hstr2_)
        print(str_)
    def Callback(self,win_pcap, param, header, pkt_data):
        if len(self.packets) > 1048576:
            self.packets.remove(self.packets[0])
        iph = unpack(self.ppkt,pkt_data[0:0xE]) 
        ipf = unpack(self.ps,pkt_data[14:34])
        #self.HexDump(pkt_data[0:0x22],"IP Frame")
        protocol = ipf[6]
        #src_mac = inet_ntom(iph[1])
        #dst_mac = inet_ntom(iph[0])
        src_ip = inet_ntoa(ipf[8])
        dst_ip = inet_ntoa(ipf[9])
        #print OuiLookup(src_mac),"->",OuiLookup(dst_mac),"=>",src_ip,"->",dst_ip
        nc = Packet(src_ip,dst_ip,protocol,ipf,iph,pkt_data,param=param,header=header)
        self.packets.append(nc)
    def Get(self,wait=False):#Gets Packet with Iteration
        if(self._iter < len(self.packets)):
            p = self.packets[self._iter]
            self._iter+=1
            return p
        else:
            if(wait):
                time.sleep(1)
                return self.Get(wait)
            else:
                return None
pm = PCAPMonitor()
pm.Capture()
Done = False
while not Done:
    packet = pm.Get(True)
    if(packet.Protocol["name"] in ["https","http"]):
        print("%s:%s -> %s:%s | Protocol: %s Service: %s"%(
            packet.source,packet.source_port,
            packet.destination,packet.destination_port,
            getProtocol(packet.protocol),
            packet.Protocol["name"] if packet.Protocol["name"] != "" else "unknown"
            )
        )
    