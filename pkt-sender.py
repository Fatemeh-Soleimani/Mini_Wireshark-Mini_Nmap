from email import message
from socket import *
from binascii import unhexlify


def sendpkt(pkt, interface):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((inter, 0))
    return s.send(pkt)


messageee = input("what is your packet content?")
messageee = " ".join(messageee[i:i+2] for i in range(0, len(messageee), 2))

inter = input("which interface do you want to use?")
packet = unhexlify(messageee).replace(" ", "")

# message="ac7ba14f4cfea18"

print("packet sent with %d byte on wlan0 " % sendpkt(packet, inter))
