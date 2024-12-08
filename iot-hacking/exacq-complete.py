#!/usr/bin/env python
import socket
import struct
import sys
import uuid

buf = ""
orig_buff = '''<?xml version="1.0" encoding="utf-8" standalone="yes" ?><s:Envelope xmlns:sc="http://www.w3.org/2003/05/soap-encoding" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">\
<s:Header><a:MessageID>urn:uuid:_MESSAGEID_</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches\
</a:Action><a:RelatesTo>urn:uuid:_PROBEUUID_</a:RelatesTo></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>uuid:1b77a2db-c51d-44b8-bf2d-418760240ab-6</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter
tds:Device</d:Types><d:Scopes>onvif://www.onvif.org/location/country/china \
 onvif://www.onvif.org/name/Amcrest \
 onvif://www.onvif.org/hardware/IP2M-841B \
 onvif://www.onvif.org/Profile/Streaming \
 onvif://www.onvif.org/type/Network_Video_Transmitter \
 onvif://www.onvif.org/extension/unique_identifier</d:Scopes>\
<d:XAddrs>http://192.168.10.10/onvif/device_service</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>'''

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('239.255.255.250', 3702))
mreq = struct.pack("=4sl", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

while True:
    print("Waiting for WS-Discovery message...\n", file=sys.stderr)
    data, addr = sock.recvfrom(1024)
    if not data:
        continue

    server_addr = addr[0]
    server_port = addr[1]
    print(f"Received from {server_addr}:{server_port}", file=sys.stderr)
    print(data, file=sys.stderr)
    print("\n", file=sys.stderr)

    # do not parse any further if this is not a WS-Discovery Probe
    if "Probe" not in data:
        continue

    # first find the MessageID tag
    m = data.find("MessageID")
    # from that point in the bugger, continue searching for "uuid" now
    u = data[m:-1].find("uuid")
    num = m + u + len("uuid:")
    # now get where the closing of the tag is
    end = data[num:-1].find("<")
    # extract the uuid number from MessageID
    orig_uuid = data [num:num+end]
    print(f"Extracted MessageID UUID {orig_uuid}", file=sys.stderr)

    # replace the _PROBEUUID_ in buffer with the extracted one
    buf = orig_buf
    buf = buf.replace("_PROBEUUID_", orig_uuid)
    # create a new random UUID for every packet
    buf = buf.replace("_MESSAGEID_", str(uuid.uuid4()))

    print(f"Sending WS reply to {server_addr}:{server_port}\n", file=sys.stderr)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.sendto(buf, (server_addr, server_port))
