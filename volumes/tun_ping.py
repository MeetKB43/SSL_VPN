#!/usr/bin/python3
import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.52.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            if pkt[IP].dst=='192.168.60.102':
                 pkt[IP].src='192.168.60.102'
                 pkt[IP].dst='192.168.52.99'
                 pkt[ICMP].type=0 
                 os.write(tun, bytes(pkt))


