# arpsoldier
Arp Spoofing More than one devices
# Example usage
```
root@192.168.1.2:scan 192.168.1.1 targets
```
scans all of device on netmask and add to targets
```
root@192.168.1.2:add target 192.168.2.3
```
optional target adding

```
root@192.168.1.2:remove target 192.168.2.3
```
optional target removing
```
root@192.168.1.2:set interface wlan0
```
optional interface setting
```
root@192.168.1.2:show <interface|status|targets>
```
shows information
```
root@192.168.1.2:start <gateway-ip>
```
starts arp spoof 
```
root@192.168.1.2:stop
```
stops arp spoof
