from socket import *
from struct import unpack


def ether(data):
    dest_mac, src_mac, proto = unpack('!6s 6s H', data[:14])
    dest_mac = ':'.join(re.findall('..', dest_mac.encode('hex')))
    src_mac = ':'.join(re.findall('..', src_mac.encode('hex')))
    return[dest_mac, src_mac, hex(proto), data[14:]]


def ip(data):
    maindata = data
    data = unpack('! B s H 2s 2s B B 2s 4s 4s', data[:20])
    return [data[0] >> 4  # version
            , (data[0] & (0x0F))*4,  # header length
            "0X"+data[1].encode('hex'),  # diffserv
            data[2],  # total length
            "0x"+data[3].encode('hex'),  # ID
            "0x"+data[4].encode('hex'),  # flags
            data[5],  # ttl
            data[6],  # protocol
            "0x"+data[7].encode('hex'),  # checksum
            socket.inet_ntoa(data[8]),  # source ip
            socket.inet_ntoa(data[9]),  # destination ip
            maindata[(data[0] & (0x0F))*4:]]  # ip payload


# def TCP(data):
#     maindata=data
#     data=unpack('! 4s 4s 2s 2s s 2s 2s 2s ',data[:20])
#     return [socket.inet_ntoa(data[1]),     #source ip
#             socket_ntoa(data[2]),          #destination ip
#             data[3],                       #seq num
#             data[4],                       #ack
#             (data[5]&(0x0F))*4,            #header length
#             "0x"+data[6].encode('hex'),    #w-size
#             "0x"+data[7].encode('hex'),    #cs4
#             "0x"+data[8].encode('hex')]   #up

def TCP(data, data_length):
    data = unpack("!H H L L H H H H", data[:20])
    return [data[0],  # source port
            data[1],  # dest port
            data[2],  # seq num
            data[3],  # ack
            data[4] & 0x0002,  # syn flag
            data[4] & 0x0004,  # ack flag
            #data[4] >> 12,
            # data[data_offset*4:data_length],
            # (data[4] >> 6) & 0x03ff , # MUST BE ZERO
            # ata[4] & 0x003f,
            # flags & 0x0020,
            # flags & 0x0010,
            # flags & 0x0008,
            # flags & 0x0004,
            # flags & 0x0002,
            # flags & 0x0001,
            data[5],  # window size
            data[6],  # check sum
            data[7]]  # urgegnt pointer


conn = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
while True:
    raw_dat, add = conn.recvfrom(65535)
    ether_shark = ether(raw_dat)
    if(ether_shark[2] == "0x800"):
        ip_shark = ip(ether_shark[3])
        if(ip_shark[6] == "0x060"):
            tcp_shark = TCP(ip_shark[3], 20)
            if(tcp_shark[4] == 1 and tcp_shark[5] == 1)
            print(f"port {tcp_shark[0]} is open on {ip_shark[9]}")
