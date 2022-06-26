from socket import *
from struct import unpack


def ether(data):
    dest_mac,src_mac,proto=unpack('!6s 6s H',data[:14])
    dest_mac=':'.join(re.findall('..',dest_mac.encode('hex')))
    src_mac=':'.join(re.findall('..',src_mac.encode('hex')))
    return[dest_mac,src_mac,hex(proto),data[14:]]
    
def ip(data):
    maindata=data
    data=unpack('! B s H 2s 2s B B 2s 4s 4s',data[:20])
    return [data[0]>>4                     #version
            ,(data[0]&(0x0F))*4,           #header length
            "0X"+data[1].encode('hex'),    #diffserv
            data[2],                       #total length
            "0x"+data[3].encode('hex'),    #ID
            "0x"+data[4].encode('hex'),    #flags
            data[5],                       #ttl
            data[6],                       #protocol
            "0x"+data[7].encode('hex'),    #checksum
            socket.inet_ntoa(data[8]),     #source ip
            socket_ntoa(data[9]),          #destination ip
            maindata[(data[0]&(0x0F))*4:]] #ip payload
    
    
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
	tcp_hdr = unpack("!2H2I4H", data[:20]) 
	src_port = tcp_hdr[0]
	dst_port = tcp_hdr[1]
	seq_num = tcp_hdr[2]
	ack_num = tcp_hdr[3]
	data_offset = tcp_hdr[4] >> 12	
	tcp_data =  data[data_offset*4:data_length]
	reserved = (tcp_hdr[4] >> 6) & 0x03ff #MUST BE ZERO
	flags = tcp_hdr[4] & 0x003f
	urg = flags & 0x0020
	ack = flags & 0x0010
	psh = flags & 0x0008
	rst = flags & 0x0004
	syn = flags & 0x0002
	fin = flags & 0x0001
	window  = tcp_hdr[5]
	checksum = tcp_hdr[6]
	urg_ptr = tcp_hdr[7]   
    
            
            
conn=socket(AF_PACKET,SOCK_RAW,ntohs(0x0003))
while True:
    raw_dat,add=conn.recvfrom(65535)
    ether_shark=ether(raw_dat)
    if(ether_shark[2]=="0x800"):
        ip_shark=ip(ether_shark[3])  
        if(ip_shark[2]=="0x060"):
            tcp_shark=TCP(ip_shark[3],20)  
    
