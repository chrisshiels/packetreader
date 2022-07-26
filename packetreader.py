#!/usr/bin/env python


import collections
import socket
import struct
import sys


# See:  /usr/include/linux/if_ether.h
ETH_P_ALL  = 0x0003
ETH_P_IP   = 0x0800
ETH_P_IPV6 = 0x86dd
ETH_P_ARP  = 0x0806


EthernetHeader = collections.namedtuple('EthernetHeader',
                                        [ 'dest',
                                          'src',
                                          'type' ])


ARPPacket = collections.namedtuple('ARPPacket',
                                   [ 'htype',
                                     'ptype',
                                     'hlen',
                                     'plen',
                                     'oper',
                                     'sha',
                                     'spa',
                                     'tha',
                                     'tpa' ])


IPHeader = collections.namedtuple('IPHeader',
                                  [ 'version',
                                    'headerlength',
                                    'tos',
                                    'length',
                                    'id',
                                    'fragmentoffset',
                                    'ttl',
                                    'protocol',
                                    'checksum',
                                    'src',
                                    'dest',
                                    'options' ])


ICMPHeader = collections.namedtuple('ICMPHeader',
                                    [ 'type',
                                      'code',
                                      'checksum',
                                      'rest' ])


TCPHeader = collections.namedtuple('TCPHeader',
                                   [ 'srcport',
                                     'destport',
                                     'sequenceno',
                                     'acknowledgementno',
                                     'headerlength',
                                     'reserved',
                                     'flags',
                                     'windowsize',
                                     'checksum',
                                     'urgent',
                                     'options' ])


UDPHeader = collections.namedtuple('UDPHeader',
                                   [ 'srcport',
                                     'destport',
                                     'length',
                                     'checksum' ])


def ipaddress(bs):
    return '.'.join(map(lambda e: '%d' % (e), bs))


def macaddress(bs):
    return ':'.join(map(lambda e: '%02x' % (e), bs))


def lookuparpoperation(operation):
    return { 1: 'request',
             2: 'reply' }.get(operation, 'unknown')


def lookupicmptype(type):
    return { 0:  'echo reply',
             3:  'destination unreachable',
             4:  'source quench',
             5:  'redirect',
             8:  'echo request',
             11: 'time exceeded',
             12: 'parameter problem',
             13: 'timestamp request',
             14: 'timestamp reply',
             15: 'information request',
             16: 'information reply',
             17: 'address mask request',
             18: 'address mask reply' }.get(type, 'unknown')


def lookuptcpflags(flags):
    flagnames = [ 'fin', 'syn', 'rst', 'psh', 'ack', 'urg' ]
    return ','.join(map(lambda e: e[1],
                        filter(lambda e: flags & 2 ** e[0],
                               zip(range(0, len(flagnames) - 1),
                                   flagnames))))


def ethernetheaderstr(ethernetheader):
    ethernetheader1 = EthernetHeader(macaddress(ethernetheader.dest),
                                     macaddress(ethernetheader.src),
                                     '0x%04x' % (ethernetheader.type))
    return str(ethernetheader1)


def arppacketstr(arppacket):
    arppacket1 = ARPPacket('0x%04x' % (arppacket.htype),
                           '0x%04x' % (arppacket.ptype),
                           arppacket.hlen,
                           arppacket.plen,
                           lookuparpoperation(arppacket.oper),
                           macaddress(arppacket.sha),
                           ipaddress(arppacket.spa),
                           macaddress(arppacket.tha),
                           ipaddress(arppacket.tpa))
    return str(arppacket1)


def ipheaderstr(ipheader):
    ipheader1 = IPHeader(ipheader.version,
                         ipheader.headerlength,
                         ipheader.tos,
                         ipheader.length,
                         ipheader.id,
                         ipheader.fragmentoffset,
                         ipheader.ttl,
                         ipheader.protocol,
                         ipheader.checksum,
                         ipaddress(ipheader.src),
                         ipaddress(ipheader.dest),
                         ipheader.options)
    return str(ipheader1)


def icmpheaderstr(icmpheader):
    icmpheader1 = ICMPHeader(lookupicmptype(icmpheader.type),
                             icmpheader.code,
                             icmpheader.checksum,
                             icmpheader.rest)
    return str(icmpheader1)


def tcpheaderstr(tcpheader):
    tcpheader1 = TCPHeader(tcpheader.srcport,
                           tcpheader.destport,
                           tcpheader.sequenceno,
                           tcpheader.acknowledgementno,
                           tcpheader.headerlength,
                           tcpheader.reserved,
                           lookuptcpflags(tcpheader.flags),
                           tcpheader.windowsize,
                           tcpheader.checksum,
                           tcpheader.urgent,
                           tcpheader.options)
    return str(tcpheader1)


def udpheaderstr(udpheader):
    return str(udpheader)


def ethernetunknown(device, ethernetheader):
    print(device, 'unknown', ethernetheaderstr(ethernetheader))
    return 1


def ipunknown(device, ethernetheader, ipheader):
    print(device, 'unknown', ethernetheaderstr(ethernetheader),
                             ipheaderstr(ipheader))
    return 1


def parseethernet(device, data):
    (dest,
     src,
     type) = struct.unpack('! 6s 6s H', data[:14])
    ethernetheader = EthernetHeader(dest,
                                    src,
                                    type)
    if type == ETH_P_ARP:
        return parsearp(device, ethernetheader, data[14:])
    elif type == ETH_P_IP:
        return parseip(device, ethernetheader, data[14:])
    elif type == ETH_P_IPV6:
        # Ignore.
        return 0
    else:
        return ethernetunknown(device, ethernetheader)


def parsearp(device, ethernetheader, data):
    (htype,
     ptype,
     hlen,
     plen,
     oper,
     sha,
     spa,
     tha,
     tpa) = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    arppacket = ARPPacket(htype,
                          ptype,
                          hlen,
                          plen,
                          oper,
                          sha,
                          spa,
                          tha,
                          tpa)
    print(device, 'arp', ethernetheaderstr(ethernetheader),
                         arppacketstr(arppacket))
    return 0


def parseip(device, ethernetheader, data):
    (versionandheaderlength,
     tos,
     length,
     id,
     fragmentoffset,
     ttl,
     protocol,
     checksum,
     src,
     dest) = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    version = versionandheaderlength >> 4
    headerlength = versionandheaderlength & 2 ** 4 - 1
    options = data[20:headerlength * 4]
    ipheader = IPHeader(version,
                        headerlength,
                        tos,
                        length,
                        id,
                        fragmentoffset,
                        ttl,
                        protocol,
                        checksum,
                        src,
                        dest,
                        options)
    if protocol == socket.IPPROTO_ICMP:
        return parseicmp(device, ethernetheader, ipheader,
                         data[headerlength * 4:])
    elif protocol == socket.IPPROTO_TCP:
        return parsetcp(device, ethernetheader, ipheader,
                        data[headerlength * 4:])
    elif protocol == socket.IPPROTO_UDP:
        return parseudp(device, ethernetheader, ipheader,
                        data[headerlength * 4:])
    else:
        return ipunknown(device, ethernetheader, ipheader)


def parseicmp(device, ethernetheader, ipheader, data):
    (type,
     code,
     checksum,
     rest) = struct.unpack('! B B H L', data[:8])
    icmpheader = ICMPHeader(type,
                            code,
                            checksum,
                            rest)
    print(device, 'icmp', ethernetheaderstr(ethernetheader),
                          ipheaderstr(ipheader),
                          icmpheaderstr(icmpheader))
    return 0


def parsetcp(device, ethernetheader, ipheader, data):
    (srcport,
     destport,
     sequenceno,
     acknowledgementno,
     headerlengthreservedandflags,
     windowsize,
     checksum,
     urgent) = struct.unpack('! H H L L H H H H', data[:20])
    headerlength = headerlengthreservedandflags >> 12
    reserved = (headerlengthreservedandflags >> 9) & 2 ** 3 - 1
    flags = headerlengthreservedandflags & 2 ** 9 - 1
    tcpheader = TCPHeader(srcport,
                          destport,
                          sequenceno,
                          acknowledgementno,
                          headerlength,
                          reserved,
                          flags,
                          windowsize,
                          checksum,
                          urgent,
                          None)
    print(device, 'tcp', ethernetheaderstr(ethernetheader),
                         ipheaderstr(ipheader),
                         tcpheaderstr(tcpheader))
    return 0


def parseudp(device, ethernetheader, ipheader, data):
    (srcport,
     destport,
     length,
     checksum) = struct.unpack('! H H H H', data[:8])
    udpheader = UDPHeader(srcport,
                          destport,
                          length,
                          checksum)
    print(device, 'udp', ethernetheaderstr(ethernetheader),
                         ipheaderstr(ipheader),
                         udpheaderstr(udpheader))
    return 0


def packetreader():
    try:
        s = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
        while True:
            match s.recvfrom(65536):
                case '', _:
                    break
                case data, senderaddress:
                    parseethernet(senderaddress[0], data)
        return 0
    except Exception as e:
        print('Error:  ' + str(e))
        return 1


def main():
    return packetreader()


if __name__ == '__main__':
    sys.exit(main())




# Todo:
# - Review parsing of different packets - ip and tcp definitely need
#   more work.
