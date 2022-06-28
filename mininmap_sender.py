from tcp_syn_sender import myfunc
from socket import *

ip = input("what is the terget ip address?")
ports = input("which ports do you want to scan?")

# range
x = ports.split("-")
temp = ""


fd = open("info.txt", 'r')
lines = fd.readlines()
dest_mac = lines[6].strip().replace(' ', '')
src_mac = lines[5].strip().replace(' ', '')
src_ip = inet_aton(lines[2]).hex()
dest_ip = inet_aton(ip).hex()
src_port = "%04x" % int(lines[3])
interface0 = lines[4].strip()
fd.close()
for i in range(int(x[0]), int(x[1])):
    dest_port = "%04x" % int(i)
    print(f"port {i} : ", end="")
    myfunc(dest_mac, src_mac, dest_ip, src_ip, dest_port, src_port, interface0)
    
