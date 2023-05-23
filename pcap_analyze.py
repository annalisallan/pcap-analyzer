import argparse #get pcap file name from command line
import os
import sys
import time

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from enum import Enum

#convert timestamp to printable format
def printable_timestamp(timestamp, resol):
    ts_sec = timestamp // resol
    ts_subsec = timestamp % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)

class PktDirection(Enum):
    not_defined = 0
    clientServer = 1
    serverClient = 2
    
    
def pcapProcess(fileName):
    #process the pcap files
    print('Opening {}...'.format(fileName))
    
    # client = '192.168.1.137:57080'
    # server = '152.19.134.43:80'

    
    (client_ip, client_port) = client.split(':')
    (server_ip, server_port) = server.split(':')
        
    count = 0
    interestingPacketsCount = 0
    
    server_seq_offset = None
    client_seq_offset = None
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(fileName):
        count += 1
        
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            #disregard LLC frames
            continue
        
        if ether_pkt.type != 0x0800:
            #disregard non-IPv4 packets
            continue
        
        ip_pkt = ether_pkt[IP] #obtain IPv4 header
        if ip_pkt.proto != 6:
            #disregard non-TCP packets
            continue
        
        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            #uninteresting source IP address
            continue
        
        if(ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            #uninteresting destination IP address
            continue
        
        tcp_pkt = ip_pkt[TCP]
        
        direction = PktDirection.not_defined
        
        if ip_pkt.src == client_ip:
            if tcp_pkt.sport != int(client_port):
                continue
            if ip_pkt.dst != server_ip:
                continue
            if tcp_pkt.dport != int(server_port):
                continue
            direction = PktDirection.clientServer
        elif ip_pkt.src == server_ip:
            if tcp_pkt.sport != int(server_port):
                continue
            if ip_pkt.dst != client_ip:
                continue
            if tcp_pkt.dport != int(client_port):
                continue
            direction = PktDirection.serverClient
        else:
            continue
        
        interestingPacketsCount += 1
        if interestingPacketsCount == 1:
            #record information about first packet
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            first_pkt_ordinal = count
            
        #record information about last packet
        last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count
        
        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp
        
        if direction == PktDirection.clientServer:
            if client_seq_offset is None:
                client_seq_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - client_seq_offset
            
        else:
            assert direction == PktDirection.serverClient
            if server_seq_offset is None:
                server_seq_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - server_seq_offset
            
        #if this TCP packet has the Ack bit set, then it must carry an ack number
        if 'A' not in str(tcp_pkt.flags):
            relative_offset_ack = 0
        else:
            if direction == PktDirection.clientServer:
                relative_offset_seq = tcp_pkt.ack - server_seq_offset
            else:
                relative_offset_seq = tcp_pkt.ack - client_seq_offset
                
        #determine the tcp payload length. IP fragmentation will mess up this logic so first check that the packet is unfragmented
        if(ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            break
        
        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
        
        #print packet information
        fmt = '[{ordnl:>5}]{ts:>10.6f}s flag={flag:<3s} seq={seq:<9d} ack={ack:<9d} len={len:<6d}'
        if direction == PktDirection.clientServer:
            fmt = '{arrow}' + fmt
            arr = '-->'
        else:
            fmt = '{arrow:>69}' + fmt
            arr = '<--'
        
        print(fmt.format(arrow = arr,
                         ordnl = last_pkt_ordinal,
                         ts = this_pkt_relative_timestamp/pkt_metadata.tsresol,
                         flag = str(tcp_pkt.flags),
                         seq = relative_offset_seq,
                         ack = relative_offset_ack,
                         len = tcp_payload_len))
    
    print('{} contains {} packets ({} interesting)'.format(fileName, count, interestingPacketsCount))
    print('First packet in connection: Packet #{} {}'.format(first_pkt_ordinal, printable_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution)))
    print('Last packet in connection: Packet #{} {}'.format(last_pkt_ordinal, printable_timestamp(last_pkt_timestamp, last_pkt_timestamp_resolution)))
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help = 'pcap file to parse', required=True)
    parser.add_argument('clientAddr', help='Specify the client pcap file name')
    parser.add_argument('serverAddr', help='Specify the server pcap file name')
    args = parser.parse_args()
    
    fileName = args.pcap
    if not os.path.isfile(fileName):
        print('"{}" does not exist'.format(fileName), file=sys.stderr)
        sys.exit(-1)
        
    client = args.clientAddr
    server = args.serverAddr
        
    pcapProcess(fileName)
    sys.exit(0)