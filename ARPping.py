#!/usr/bin/python3
import sys
from scapy.all import srp, Ether,ARP,conf
from scapy.sendrecv import sr
from scapy.layers.inet import IP


class ARPPing:
    def __init__(self, destination):
        self.destination = destination
    def scan_arp(self):
        return srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.destination), timeout=5)


def main():
    arp = ARPPing("192.168.1.0/24")
    ans , unans = arp.scan_arp()
    ans.summary()


if __name__=="__main__":
    main()


