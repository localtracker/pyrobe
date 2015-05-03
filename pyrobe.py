#!/usr/bin/env python
import sys
from netaddr import *
from scapy.all import *
from subprocess import *
import datetime
import time                                               # import all the needed libraries

call(["clear"])                                           #clear the console
                                                          # set date-time parameters
today = datetime.date.today()
d=today.strftime("%d, %b %Y")
tf=time.strftime(" %H:%M")
t=time.strftime(" %H:%M:%S")
                                                          # print sexy ascii art
print "    ____        ____        __        "
print "   / __ \__  __/ __ \____  / /_  ___  "
print "  / /_/ / / / / /_/ / __ \/ __ \/ _ \ "
print " / ____/ /_/ / _, _/ /_/ / /_/ /  __/ "
print "/_/    \__, /_/ |_|\____/_.___/\___/  "
print "      /____/                          "
print "--------------------------------------"	
print "Probe Investigator // dev:localtracker"
print "--------------------------------------"
                                                          # accept input from user for choosing interface

intf = raw_input("Enter the Name of the interface to sniff: ")
print "\n"
if intf == "":
	print "Please choose a monitor interface"
	intf = raw_input("Enter the Name of the interface to sniff: ")
                                                          # create the log file
f = open("ProbeLog"+str(today)+str(tf)+".txt","w")
                                                          # define variables
clients = []
uni = 0
mach = []
manu =[]
                                                          # our main function
def phandle(p):	
    global uni    
    if p.haslayer(Dot11ProbeReq):                         # check if packet contains a probe request layer
        mac = p.addr2
        if p.haslayer(Dot11Elt):                          # check if information element is present
            if p.ID == 0: 
                ssid = p.info                             # extract ssid
                if ssid not in clients and ssid != "":
                    clients.append(ssid)		  # lookup MAC address against IEEE OUI database
		    macad = EUI(mac)
                    print len(clients),mac+" ("+macad.oui.registration().org+") <--Probing--> "+ssid
		    f.write (str(len(clients))+"//"+mac+" ("+macad.oui.registration().org+") <--Probing--> "+ssid+"\n")
		    if mac not in mach:
                        mach.append(mac)
                        uni+=1                            # increment unique MAC counter
		    		 
sniff(iface=intf,prn=phandle, store=0)                    # our sniff function
print ("\n")
print "Unique MACs: ",uni
f.write ("\nUnique MACs: "+str(uni))
f.write ("\nScan performed on: "+str(d)+" at"+str(t))  
f.close()                                                 # close the log file