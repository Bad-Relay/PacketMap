import socket
import struct
import textwrap
import os
from Tkinter import *
#computer host
host = "192.168.99.149"

root = Tk()

#make a new socket
if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

#add ip header to sooket
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)

#promiscuous mode on
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
#set var for gui
packet = StringVar()
packet.set(sniffer.recvfrom(65565))
#print in consol
print sniffer.recvfrom(65565)

#set packet
label = Label(root, text= packet.get())
label.pack()
#promiscuous mode off
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)#
#run gui
root.mainloop()