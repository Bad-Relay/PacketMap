import socket
import struct
import textwrap
import os
import Tkinter as tk
from Tkinter import *
from ctypes import *
from OpenGL.GLUT import *
from OpenGL.GLU import *
from OpenGL.GL import *
import time
#from PIL import ImageTk,Image

# GUI host
root = Tk()

# Defult Ip
host = socket.gethostbyname(socket.gethostname())
host = str(host)

# Name of OpenGL
name = 'Packet Map'

# Set Var For Packet
packet = StringVar()

ttl = 'Windows'

#img = ImageTk.PhotoImage(Image.open("windows.png"))
#canvas = Canvas(root, width=50, height=50)

# Cap Drop down box

optVar = StringVar(root)

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

        self.ttl_number = self.ttl

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))


        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

def capture_packet():

    #IP var from text box
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


    #print in console
    raw_buffer = sniffer.recvfrom(65565)[0]

    # create an IP header from the first 20 bytes of the buffer
    ip_header = IP(raw_buffer[0:20])

    # Os Detection

    if ip_header.ttl_number == 128:
        ttl = 'Windows'
    elif ip_header.ttl_number == 64:
        ttl = 'Linux'
    elif ip_header.ttl_number == 255:
        ttl = 'Cisco'
    elif ip_header.ttl_number == 1:
        ttl = 'Router'
    elif ip_header.ttl_number == 2:
        ttl = 'Router'
    else:
        ttl = 'Unknown'


    packetStr = ("Protocol: %s %s -> %s OS: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, ttl))
    packet.set(packetStr)

    print "Protocol: %s %s -> %s OS: %s Version: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address,
                                            ip_header.ttl_number,ip_header)

    #promiscuous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)#
    return packet.get()

def getOS():
    # IP var from text box
    host = e.get()

    # make a new socket
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    sniffer.bind((host, 0))

    # add ip header to sooket
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # promiscuous mode on
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # print in console
    raw_buffer = sniffer.recvfrom(65565)[0]

    # create an IP header from the first 20 bytes of the buffer
    ip_header = IP(raw_buffer[0:20])

    # Os Detection

    if ip_header.ttl_number == 128:
        ttl = 'Windows'
    elif ip_header.ttl_number == 64:
        ttl = 'Linux'
    elif ip_header.ttl_number == 255:
        ttl = 'Cisco'
    elif ip_header.ttl_number == 1:
        ttl = 'Router'
    elif ip_header.ttl_number == 2:
        ttl = 'Router'
    else:
        ttl = 'Unknown'

    print "Protocol: %s %s -> %s OS: %s " % (
    ip_header.protocol, ip_header.src_address, ip_header.dst_address,
    ttl)

    return ttl



def display():

   glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
   glPushMatrix()
   if ttl == getOS():
    color = [1.0, 0., 0., 1.]
   else:
    color = [2.0, 2., 2., 2.]

   glMaterialfv(GL_FRONT, GL_DIFFUSE, color)
   glutSolidSphere(2, 20, 20)
   glPopMatrix()
   glutSwapBuffers()
   return

def map():

# Place holder for the map

    glutInit(sys.argv)
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB | GLUT_DEPTH)
    glutInitWindowSize(400, 400)
    glutCreateWindow(name)
    glClearColor(0., 0., 0., 1.)
    glShadeModel(GL_SMOOTH)
    glEnable(GL_CULL_FACE)
    glEnable(GL_DEPTH_TEST)
    glEnable(GL_LIGHTING)
    lightZeroPosition = [10., 4., 10., 1.]
    lightZeroColor = [0.8, 1.0, 0.8, 1.0]  # green tinged
    glLightfv(GL_LIGHT0, GL_POSITION, lightZeroPosition)
    glLightfv(GL_LIGHT0, GL_DIFFUSE, lightZeroColor)
    glLightf(GL_LIGHT0, GL_CONSTANT_ATTENUATION, 0.1)
    glLightf(GL_LIGHT0, GL_LINEAR_ATTENUATION, 0.05)
    glEnable(GL_LIGHT0)
    glutDisplayFunc(display)
    glMatrixMode(GL_PROJECTION)
    gluPerspective(40., 1., 1., 40.)
    glMatrixMode(GL_MODELVIEW)
    gluLookAt(0, 0, 10,
              0, 0, 0,
              0, 1, 0)
    glPushMatrix()
    glutMainLoop()


#for runing capture packet a numner of times
def packetrun():


    packetNum = int(cE.get())
    optBox = optVar.get()
    scrollbar = Scrollbar(root)
    scrollbar.pack(side=RIGHT, fill=Y)
    packetList = Listbox(root, width=55, height=20, yscrollcommand=scrollbar.set)


    if optBox == 'Packets':
        for x in range(0, packetNum):
            packetList.insert(END, capture_packet())



    elif optBox == 'Time':
        for x in range(0, packetNum):
            t_end = time.time() + 60 * packetNum
            while time.time() < t_end:
                packetList.insert(END, capture_packet())

    Button(root, text='Map', command=map)
    packetList.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=packetList.yview)



# enter ip text box
Label(root, text="IP").grid(row=0)

# IP text box entry
e = Entry(root)
e.grid(row=0, column=1)
e.insert(END, host)

# Cap options text box
Label(root, text="Options").grid(row=1)

# Cap Options for drop down
choices = {'Packets', 'Time', 'Live'}
optVar.set('Packets')  # set the default option

# Cap entry
cE = Entry(root)
cE.grid(row=1, column=2)
cE.insert(END, '1')

popupMenu = OptionMenu(root, optVar, *choices)
popupMenu.grid(row=1, column =1)

# Start button
Button(root, text='Start', command=packetrun).grid(row=3, column=0, sticky=W, pady=4)


# Quit button
Button(root, text='Quit', command=root.quit).grid(row=3, column=1, sticky=W, pady=4)

# Map Button
Button(root, text='Map', command=map).grid(row=3, column=2, sticky=W, pady=4)

root.mainloop()

