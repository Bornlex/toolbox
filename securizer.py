#! /usr/bin/python

#the purpose of this script is to prevent Man in the middle attack by analyzing packets received by looking at the destination field in the packet and checking if the MAC address is the same that the MAC address of the current computer

from scapy.all import *
import re

#gateway to adapt to the wifi router the computer is connected on
gatewayIP="192.168.1.1"
interface="wlan0"
gatewayMAC="ff:ff:ff:ff:ff:ff"
computerMAC="e4:ce:8f:2e:3e:de"


def pkt_callback(pkt):
    if pkt.dst == computerMAC and pkt.src != gatewayMAC:
        print("[!] problem with destination or source of packets received, please check if this is not a man in the middle attack")
        print("[!] pkt.src: {src} -> pkt.dst: {dst}".format(src=pkt.src, dst=pkt.dst))


def get_mac(IP):
    print("[*] Getting gateway MAC address...")
    conf.verb=0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

print("[*] Launching service...")
gatewayMAC = get_mac(gatewayIP)
print("[*] Service running...")
sniff(iface="wlan0", prn=pkt_callback, filter="tcp", store=0)
