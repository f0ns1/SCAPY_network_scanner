#!/usr/bin/python3

import scapy.all
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr

class ACKScan:
    def __init__(self, destination, ports):
        self.destination= destination
        self.ports=ports

    def response_ports(seld,ans):
        for s,r in ans:
            print("Send ACK package: ", s.summary() )
            print("Response ACK:  ",r.summary())

    def not_response(self, unans):
        for r in unans:
            print("Not response : ", r.summary())

    def ack(self):
        return sr(IP(dst=self.destination)/TCP(dport=self.ports, flags="A"),timeout=2)

def main():
    ports=[]
    target="192.168.1.63"
    for i in range(65535):
        ports.append(1)
    ack= ACKScan("192.168.1.1",ports)
    ans, unans= ack.ack()
    ack.response_ports(ans)
    #ack.not_response(unans)
    print("Not filtered ports: ", len(ans))
    print("Filtered ports : ", len(unans))

if __name__=="__main__":
    main()



