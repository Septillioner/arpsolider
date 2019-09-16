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
def HexDump(chunk,name="Chunk"):
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
            h_size = _f+0x22 #+ tcph_length * 4
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
    def cwith(self,target):
        return self.source == target or self.destination == target
class SSLSoldier:
    h0 = "!BHH"
    handshake_h0 = "!B3sH"
    SSLVersions={
        0x300:"SSL 3.0",
        0x301:"TLS 1.0",
        0x302:"TLS 1.1",
        0x303:"TLS 1.2"
    }
    V_SSL_3_0 = 0x300
    V_TLS_1_0 = 0x301
    V_TLS_1_1 = 0x302
    V_TLS_1_2 = 0x303
    ContentTypes={
        0x16:"Handshake",
        0x17:"Application_Data",
        0x14:"Change_Cipher_Spec",
        0x15:"Alert"
    }
    CT_Handshake=0x16
    CT_Application_Data=0x17
    CT_Change_Cipher_Spec=0x14
    CT_Alert=0x15
    HandshakeTypes={
        "hello_request":0x00,
        "client_hello":0x01,
        "server_hello":0x02,
        "certificate":0x0b,
        "server_key_exchange":0x0c,
        "certificate_request":0x0d,
        "server_hello_done":0x0e,
        "certificate_verify":0x0f,
        "client_key_exchange":0x10,
        "finished":0x14
    }
    HT_hello_request=0x00
    HT_client_hello=0x01
    HT_server_hello=0x02
    HT_certificate=0x0b
    HT_server_key_exchange=0x0c
    HT_certificate_request=0x0d
    HT_server_hello_done=0x0e
    HT_certificate_verify=0x0f
    HT_client_key_exchange=0x10
    HT_finished=0x14
    def __init__(self,target="127.0.0.1"):
        self.target= target
        self.ConnectionPackets = []
    def AnalyzeSSLPacket(self,packet):
        sdata = packet.db
        _ = {}
        try:
            header_0 = unpack(self.h0,sdata[0:5])
            content_type = header_0[0]
            version = header_0[1]
            length = header_0[2]
            _["_content-type"] = header_0[0]
            _["content-type"] = self.ContentTypes[header_0[0]]
            _["_version"] = header_0[1]
            _["version"] = self.SSLVersions[header_0[1]]
            _["length"] = header_0[2]
        except:
            return None
        
        sslpacket = sdata[0x5:0x5+header_0[2]]
        if(content_type == self.CT_Handshake):
            pass
        return _
    def Look(self,packet):
        if packet.Protocol["name"] == "https" and packet.cwith("160.153.133.165"):
            #HexDump(packet.db[0:16])
            SSLPacket = self.AnalyzeSSLPacket(packet)
            if(SSLPacket):
                print("%s:%s -> %s:%s | Protocol: %s Service: %s Length: %s CT:%s Version:%s CL:%s"%(
                    packet.source,packet.source_port,
                    packet.destination,packet.destination_port,
                    getProtocol(packet.protocol),
                    packet.Protocol["name"] if packet.Protocol["name"] != "" else "unknown",
                    len(packet.data),
                    SSLPacket["content-type"],
                    SSLPacket["version"],
                    SSLPacket["length"],
                    )
                )
            else:
                print("%s:%s -> %s:%s | Protocol: %s Service: %s Length: %s"%(
                    packet.source,packet.source_port,
                    packet.destination,packet.destination_port,
                    getProtocol(packet.protocol),
                    packet.Protocol["name"] if packet.Protocol["name"] != "" else "unknown",
                    len(packet.data)
                    )
                )
    
pm = PCAPMonitor()
pm.Capture()
ss = SSLSoldier("192.168.1.2")
Done = False
while not Done:
    packet = pm.Get()
    if packet:
        ss.Look(packet)
        #if(packet.Protocol["name"] in ["https","http"]):
        #    print("%s:%s -> %s:%s | Protocol: %s Service: %s Length: %s"%(
        #        packet.source,packet.source_port,
        #        packet.destination,packet.destination_port,
        #        getProtocol(packet.protocol),
        #        packet.Protocol["name"] if packet.Protocol["name"] != "" else "unknown",
        #        len(packet.data)
        #        )
        #    )
    