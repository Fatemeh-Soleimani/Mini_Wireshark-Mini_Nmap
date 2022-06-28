from socket import *
from email import message
from binascii import *
from checksum3 import *
from pkt_sender import *
from sys import *


def myfunc():
    fd = open("info.txt", 'r')
    lines = fd.readlines()

    # link
    dest_mac = lines[6].strip().replace(' ', '')
    src_mac = lines[5].strip().replace(' ', '')
    proto3 = "0800"

    # ip
    ver = "45"
    diff = "00"
    t_len = "0028"
    id = "07c3"
    flags = "4000"
    ttl = "40"
    proto4 = "06"
    cs3 = "0000"
    src_ip = inet_aton(lines[2]).hex()
    dest_ip = inet_aton(lines[0]).hex()

    # tcp
    src_port = "%04x" % int(lines[3])
    dest_port = "%04x" % int(lines[1])
    seq_num = 'c039a735'
    ack = "00000000"
    # hlen + flags
    h_len = "5002"
    w_size = "7210"
    cs4 = "0000"
    up = "0000"

    # interface
    interface0 = lines[4].strip()

    # checksum ip
    ipcs = ver + diff + t_len + id + flags + ttl + proto4 + cs3 + src_ip + dest_ip

    # checksum tcp
    tcpcs = src_ip + dest_ip + '00' + proto4 + '0014' + src_port + \
        dest_port + seq_num + ack + h_len + w_size + cs4 + up

    # update checksum
    cs3 = cs(ipcs)
    cs4 = cs(tcpcs)

    # pkt

    # link
    pkt = dest_mac
    pkt += src_mac
    pkt += proto3
    # ip
    pkt += ver
    pkt += diff
    pkt += t_len
    pkt += id
    pkt += flags
    pkt += ttl
    pkt += proto4
    pkt += cs3
    pkt += src_ip
    pkt += dest_ip
    # tcp
    pkt += src_port
    pkt += dest_port
    pkt += seq_num
    pkt += ack
    pkt += h_len
    pkt += w_size
    pkt += cs4
    pkt += up

    print(f"packet sent with %d byte on {interface0} " % sendpkt(
        pkt, interface0))


myfunc()
