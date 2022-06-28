from socket import *
from struct import unpack
import re

myport=3000

def ether(data):
    dest_mac, src_mac, proto = unpack('!6s 6s H', data[:14])
    dest_mac = ':'.join(re.findall('..', dest_mac.hex()))
    src_mac = ':'.join(re.findall('..', src_mac.hex()))
    return[dest_mac, src_mac, hex(proto), data[14:]]


def ip(data):
    maindata = data
    data = unpack('! B s H 2s 2s B B 2s 4s 4s', data[:20])
    return [data[0] >> 4  # version
            , (data[0] & (0x0F))*4,  # header length
            "0X"+data[1].hex(),  # diffserv
            data[2],  # total length
            "0x"+data[3].hex(),  # ID
            "0x"+data[4].hex(),  # flags
            data[5],  # ttl
            data[6],  # protocol
            "0x"+data[7].hex(),  # checksum
            inet_ntoa(data[8]),  # source ip
            inet_ntoa(data[9]),  # destination ip
            maindata[(data[0] & (0x0F))*4:]]  # ip payload


def TCP(data):

    
    data = unpack("!H H L L H H H H", data[:20])
    return [data[0],  # source port
            data[1],  # dest port
            data[2],  # seq num
            data[3],  # ack
            data[4] & 0x0002,  # syn flag
            data[4] & 0x0010,  # ack flag
            data[5],  # window size
            data[6],  # check sum
            data[7]]  # urgegnt pointer


conn = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
while True:
    raw_dat, add = conn.recvfrom(65535)
    ether_shark = ether(raw_dat)

    if(ether_shark[2] == "0x800"):
        ip_shark = ip(ether_shark[3])
        if(ip_shark[7] == 6):
            tcp_shark = TCP(ip_shark[11])
            #if(tcp_shark[0]==myport):
            print(f"3:{tcp_shark[4]}       {tcp_shark[5]}")
            if(tcp_shark[4] == 2 and tcp_shark[5] == 16):
                print(f"port {tcp_shark[0]} is open on {ip_shark[9]}")
