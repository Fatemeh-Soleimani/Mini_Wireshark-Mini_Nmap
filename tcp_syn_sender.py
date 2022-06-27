from socket import *
from email import message
from binascii import *
from checksum3 import *
from pkt_sender import *
from sys import *


fd = open("info.txt", 'r')
lines = fd.readlines()

dest_mac = lines[6][:17]
src_mac = lines[5][:17]
proto3 = "08 00"

ver = "45"
# head len
# fragment offset
diff = "00"
t_len = "00 28"
id = "07 c3"
flags = "40 00"
ttl = "40"
proto4 = "06"
cs3 = "00 00"
src_ip = inet_aton(lines[2]).encode("hex")
dest_ip = inet_aton(lines[0]).encode("hex")


src_port = "%04x" % int(lines[3])
dest_port = "%04x" % int(lines[1])
seq_num = "17 40 30 d1"
ack = "00 00 00 00"
h_len = "50 02"
w_size = "72 10"
cs4 = "00 00"
up = "00 00"

interface0 = lines[4].strip()

# checksum ip
ipcs = ""
ipcs += ver
# header length   ??????????????
ipcs += diff
ipcs += t_len
ipcs += id
ipcs += flags
ipcs += ttl
ipcs += proto4
ipcs += cs3
ipcs += src_ip
ipcs += dest_ip

# checksum tcp
tcpcs = ""
tcpcs += src_port
tcpcs += dest_port
tcpcs += seq_num
tcpcs += ack
tcpcs += h_len
tcpcs += w_size
tcpcs += cs4
tcpcs += up
# tcp pseudo header
reserved = "00"
tcpcs += src_ip
tcpcs += dest_ip
tcpcs += reserved
tcpcs += proto4
tcpcs += h_len

# update checksum
cs3 = cs(ipcs)
cs4 = cs(tcpcs)

# pkt
pkt = dest_mac
pkt += src_mac
pkt += proto3

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

pkt += src_port
pkt += dest_port
pkt += seq_num
pkt += ack
pkt += h_len
pkt += w_size
pkt += cs4
pkt += up


print("packet sent with %d byte on wlan0 " % sendpkt(pkt, interface0))

