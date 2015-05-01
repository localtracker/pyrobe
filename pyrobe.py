#!/usr/bin/env python
import sys
from scapy.all import *
from subprocess import *
import datetime
import time

call(["clear"])

today = datetime.date.today()
d=today.strftime("%d, %b %Y")
tf=time.strftime(" %H:%M")
t=time.strftime(" %H:%M:%S")



print "    ____        ____        __        "
print "   / __ \__  __/ __ \____  / /_  ___  "
print "  / /_/ / / / / /_/ / __ \/ __ \/ _ \ "
print " / ____/ /_/ / _, _/ /_/ / /_/ /  __/ "
print "/_/    \__, /_/ |_|\____/_.___/\___/  "
print "      /____/                          "
print "--------------------------------------"	
print "Probe Investigator // dev:localtracker"
print "--------------------------------------"

intf = raw_input("Enter the Name of the interface to sniff: ")
print "\n"
if intf == "":
	print "Please choose a monitor interface"
	intf = raw_input("Enter the Name of the interface to sniff: ")

f = open("ProbeLog"+str(today)+str(tf)+".txt","w")

clients = []
uni = 0
mach = []
manu =[]
def phandle(p):	
    global uni    
    if p.haslayer(Dot11ProbeReq):
        mac = p.addr2
        if p.haslayer(Dot11Elt):
            if p.ID == 0:
                ssid = p.info
                if ssid not in clients and ssid != "":
                    clients.append(ssid)
                    print len(clients),mac+" <--Probing--> "+ssid
		    f.write (str(len(clients))+"//"+mac+" <--Probing--> "+ssid+"\n")
		    if mac not in mach:
                        mach.append(mac)
                        uni+=1
		    		    

sniff(iface=intf,prn=phandle, store=0)
print ("\n")
print "Unique MACs: ",uni
f.write ("\nUnique MACs: "+str(uni))
f.write ("\nScan performed on: "+str(d)+" at"+str(t))
f.close()