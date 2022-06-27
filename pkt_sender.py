from socket import *
from binascii import unhexlify

def sendpkt(pkt, interface):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    return s.send(unhexlify(pkt))
 
if __name__ == '__main__':
    
    messageee = input("what is your packet content?")
   
    inter = input("which interface do you want to use?")
    print(f"packet sent with %d byte on  {inter}" % sendpkt(messageee, inter))
