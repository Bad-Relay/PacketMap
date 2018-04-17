import socket
import struct
import textwrap
import os
from Tkinter import *
from ctypes import *
from OpenGL.GLUT import *
from OpenGL.GLU import *
from OpenGL.GL import *
from PIL import ImageTk,Image
#computer host
root = Tk()

#Defult Ip
host = "192.168.99.110"

#Name of OpenGL
name = 'Packet Map'

img = ImageTk.PhotoImage(Image.open("windows.png"))
canvas = Canvas(root, width=50, height=50)
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

    # Os Detection
    ttl = '0'
    if ip_header.ttl_number == 128:
        ttl = 'Windows'
    elif ip_header.ttl_number == 64:
        ttl = 'Linux'
    elif ip_header.ttl_number == 255:
        ttl = 'Cisco'

    packet.set("Protocol: %s %s -> %s OS: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, ttl))
    #print in console
    raw_buffer = sniffer.recvfrom(65565)[0]

    # create an IP header from the first 20 bytes of the buffer
    ip_header = IP(raw_buffer[0:20])

    print "Protocol: %s %s -> %s OS: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address,
                                            ip_header.ttl_number)


    #set packet gui


    label = Label(root, text= packet.get())
    label.pack()



    #put in picture needs to be worked on

    #canvas.pack()
    #canvas.create_image(20, 15, anchor=NW, image=img)

    #promiscuous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)#



def display():
   glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
   glPushMatrix()
   color = [1.0, 0., 0., 1.]
   glMaterialfv(GL_FRONT, GL_DIFFUSE, color)
   glutSolidSphere(2, 20, 20)
   glPopMatrix()
   glutSwapBuffers()
   return

def map():

#Place holder for the map

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
    for x in range(0, 10):
        capture_packet()

# enter ip text box
Label(root, text="IP").grid(row=0)

# IP text box entry
e = Entry(root)
e.grid(row=0, column=1)

#Start button
Button(root, text='Start', command=capture_packet).grid(row=3, column=0, sticky=W, pady=4)

#Quit button
Button(root, text='Quit', command=root.quit).grid(row=3, column=1, sticky=W, pady=4)

#Map Button
Button(root, text='Map', command=map).grid(row=3, column=2, sticky=W, pady=4)

root.mainloop()

