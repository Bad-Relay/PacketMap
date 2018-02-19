import socket
import struct
import textwrap
import os
from Tkinter import *
from ctypes import *
#computer host
root = Tk()

#Defult Ip
host = "192.168.99.149"

#Ip header table
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

def capture_packet():

    host = e.get()

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
    raw_buffer = sniffer.recvfrom(65565)[0]
    ip_header = IP(raw_buffer[0:20])
    packet.set("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    #print in console
    raw_buffer = sniffer.recvfrom(65565)[0]

    # create an IP header from the first 20 bytes of the buffer
    ip_header = IP(raw_buffer[0:20])

    print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
    #set packet gui
    label = Label(root, text= packet.get())
    label.pack()
    #promiscuous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)#
    #run gui

# enter ip text box
Label(root, text="IP").grid(row=0)

# IP text box entry
e = Entry(root)
e.grid(row=0, column=1)

#Start button
Button(root, text='Start', command=capture_packet).grid(row=3, column=0, sticky=W, pady=4)

#Quit button
Button(root, text='Quit', command=root.quit).grid(row=3, column=1, sticky=W, pady=4)

root.mainloop()

