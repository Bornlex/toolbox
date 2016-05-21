#! /usr/bin/python


from scapy.all import *
import os
import re
import scapy_http.http
from scapy_http.http import HTTPRequest
from threading import Thread, Event
import sys


HOST_REGEXP="(?<=\r\Host\: )([A-Za-z\.]){4,40}(?=\r\n)"

class PacketContent():
    def __init__(self, method_=None, cookie_=None, host_=None):
        self.method=method_
        self.cookie=cookie_
        self.host=host_


class MailSniffer():
    def __init__(self):
        self.filename = "mail_packets.txt"
        self.filtering = "tcp port 110 or tcp port 25 or tcp port 143"

    def packet_callback(self):
        f = open(self.filename, 'w')
        if packet[TCP].payload:
            mail_packet = str(packet[TCP].payload)
            if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
                print("[*] Server : %s" % packet[IP].dst)
                print("[*] %s" % packet[TCP].payload)
                f.write("[*] Server : %s" % packet[IP].dst)
                f.write("[*] %s" % packet[TCP].payload)

    def run(self):
        print("Mailsniffer running...")
        sniff(filter=self.filtering, prn=self.packet_callback, store=0)

class HTTPSSniffer(Thread):
    def __init__(self, store_=False):
        print("[*] initializing sniffer...")
        super(HTTPSSniffer, self).__init__()
        self._stop = Event()
        self.store = store_
        self.filename = "internet_packets_HTTPS.txt"

    def get_http_callback(self, pkt):
        try:
            print("[*][HTTPS] connection")
            #do something
        except:
            pass
            
    def run(self):
        print("[*] https internet sniffer running...")
        sniff(iface="wlan0", prn=self.get_http_callback, store=0)

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()
        

class HTTPSniffer(Thread):
    def __init__(self, myIP_, store_=False):
        print("[*] initializing sniffer...")
        super(HTTPSniffer, self).__init__()
        self._stop = Event()
        self.store = store_
        self.filename = "internet_packets.txt"
        self.content=None
        self.myIP=myIP_

    def get_http_callback(self, pkt):
        if not pkt.haslayer(HTTPRequest):
            return
        http_layer = pkt.getlayer(HTTPRequest)
        try:
            if pkt[IP].src != self.myIP or pkt[IP].dst != self.myIP:
                print("[sniffer][*] connection detected")
                print("\t{src} -> {dst}".format(src=pkt[IP].src, dst=pkt[IP].dst))
            return
            print("[*][{method}] connection".format(method=pkt[HTTPRequest].fields["Method"]))
            print("\t[host] host visited : {host}".format(host=pkt[HTTPRequest].fields["Host"]))
            if "Cookie" in pkt[HTTPRequest].fields:
                print("\t[cookie] {c}".format(c=pkt[HTTPRequest].fields["Cookie"]))
            packet_content=PacketContent(pkt[HTTPRequest].fields["Method"], host=pkt[HTTPRequest].fields["Cookie"], cookie=pkt[HTTPRequest].fields["Host"])
            self.content=packet_content
        except Exception, e:
            print("[!] error occured : {mess}".format(mess=str(e)))
            
    def run(self):
        print("[*] internet sniffer running...")
        sniff(iface="wlan0", prn=self.get_http_callback, store=0)

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

if __name__ == "__main__":
    sniffers = []
    #internet_sniffer_HTTPS = HTTPSSniffer()
    internet_sniffer_HTTP = HTTPSniffer("192.168.1.52")
    #sniffers.append(internet_sniffer_HTTPS)
    sniffers.append(internet_sniffer_HTTP)

    try:
        for s in sniffers:
            s.start()
    except KeyboardInterrupt:
        for s in sniffers:
            s.stop()
        sys.exit(1)
