import socket
import struct
import textwrap
import os
from Tkinter import *
#computer host
root = Tk()

#Defult Ip
host = "192.168.99.149"


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

