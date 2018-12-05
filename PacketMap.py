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
from OpenGL._bytes import *
import time
import pygeoip
#from PIL import ImageTk,Image

gi = pygeoip.GeoIP('GeoIP.dat')
# GUI host
root = Tk()

menuStart = 1

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

#start packet capture var
start = 1




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

class packet():
    def __init__(self, protocol, srcAddress, dstAddress, ttl):
        self.protocol = protocol
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.ttl = ttl

def capture_packet():
    start = 1

    #IP var from text box
    #host = e.get()

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

    protocol = ip_header.protocol

    srcAddress = ip_header.src_address

    dstAddress = ip_header.dst_address

  #  packetStr = ("Protocol: %s %s -> %s OS: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, ttl))
  #  packet.set(packetStr)

    print "Protocol: %s %s -> %s OS: %s Version: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address,
                                            ip_header.ttl_number,ip_header)

    #promiscuous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    return packet(protocol,srcAddress,dstAddress,ttl)


def display():
   glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
   glPushMatrix()
   glutSolidTeapot(.5)
   for x in range(0, 2):
       packetCapture = capture_packet()
       if ttl == packetCapture.ttl:
           color = [1.0, 0., 0., 1.]
       else:
           color = [2.0, 2., 2., 2.]
       glTranslatef(0., -1.5, 0.)
       glMaterialfv(GL_FRONT, GL_DIFFUSE, color)
       glutSolidSphere(.5, 20, 20)

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

class MainWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)


        container = tk.Frame(self)

        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (mainMenu, packetMenu):
            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(mainMenu)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class mainMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        optVar = StringVar(self)
        # enter ip text box
        tk.Label(self, text="IP").grid(row=0)

        # Cap options text box
        tk.Label(self, text="Options").grid(row=1)

        # Cap Options for drop down
        choices = {'Packets', 'Time', 'Live'}
        optVar.set('Packets')  # set the default option

        # Cap entry
        cE = tk.Entry(self)
        cE.grid(row=1, column=2)
        cE.insert(END, '1')

        popupMenu = tk.OptionMenu(self, optVar, *choices)
        popupMenu.grid(row=1, column =1)

        # Start button
        startBut = tk.Button(self, text='Start', command=lambda: controller.show_frame(packetMenu))

        startBut.grid(row=3, column=1, sticky=W, pady=4)

        #quitBut = tk.Button(self, text='Quit', command=root.quit)
        #quitBut.grid(row=3, column=3, sticky=W, pady=4)

        # Map Button
        mapBut = tk.Button(self, text='Map', command=map)
        mapBut.grid(row=3, column=2, sticky=W, pady=4)


class packetMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        #capture_packet()
        #tk.Label(self, text="Packet").grid(row=0)

        # for runing capture packet a numner of times

        # popupMenu.destroy()
        # mapBut.destroy()

        #packetCapture = capture_packet()
        #packetNum = int(cE.get())


        #optBox = optVar.get()

        tk.Label(self, text="IP").grid(row=0)

        # IP text box entry
        e = tk.Entry(self)
        e.grid(row=0, column=1, sticky=W, pady=4)
        e.insert(END, host)



        scrollbar = tk.Scrollbar(self)
        scrollbar.pack(side=RIGHT, fill=Y)
        scrollbar.grid(row=2, column=1)
        packetList = tk.Listbox(self, width=80, height=20, yscrollcommand=scrollbar.set)
        packetList.grid(row=2, column=1)
        # geoIp = geolite2.lookup('17.0.0.1')

        tk.Label(self, text="Sort").grid(row=1, column=0, sticky=W, pady=4)
        startOverBut = tk.Button(self, text='Start Over', command=lambda: controller.show_frame(mainMenu))
        startOverBut.grid(row=3, column=2, sticky=W, pady=4)
        startBox = tk.Button(self, text='Start Box', command=lambda: packetBox(packetList, scrollbar))
        startBox.grid(row=3, column=1, sticky=W, pady=4)
        sortChoices = {'Ip Source', 'IP Dest', 'Location'}
        sort = tk.OptionMenu(self, 'Ip Source', *sortChoices)
        sort.grid(row=1, column=1, sticky=W, pady=4)
        packetBox(packetList,scrollbar)
        packetBox(packetList, scrollbar)


def packetBox(packetList,scrollbar):
    packetNum = 1
    optBox = 'Packets'
    if optBox == 'Packets':
        packetCapture = capture_packet()
        for x in range(0, packetNum):
            #geoIp.timezone
            packetList.insert(END, "Protocol: %s %s -> %s OS: %s Location: %s" % (
            packetCapture.protocol, packetCapture.srcAddress, packetCapture.dstAddress,
            packetCapture.ttl, gi.country_name_by_addr(packetCapture.dstAddress)))

    elif optBox == 'Time':
        packetCapture = capture_packet()
        for x in range(0, packetNum):
            t_end = time.time() + 60 * packetNum
            while time.time() < t_end:
                capture_packet()
                tk.packetList.insert(END, "Protocol: %s %s -> %s OS: %s " % (
                packetCapture.protocol, packetCapture.srcAddress, packetCapture.dstAddress,
                    packetCapture.ttl))

            packetList.pack(side=LEFT, fill=BOTH, expand=True)
            #Button(self, text='Quit', command=root.quit, width=55, height=20)
            scrollbar.config(command=packetList.yview)




app = MainWindow()
app.mainloop()
