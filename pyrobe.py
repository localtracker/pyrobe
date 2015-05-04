#!/usr/bin/env python
import sys
from netaddr import *
from scapy.all import *
from subprocess import *
import datetime
import time                                               # import all the needed libraries

call(["clear"])                                           # clear the console
                                                          
today = datetime.date.today()				  # set date-time parameters
d=today.strftime("%d, %b %Y")
tf=time.strftime(" %H:%M")
t=time.strftime(" %H:%M:%S")
                                                          # print sexy ascii art
print "    ____        ____        __        "
print "   / __ \__  __/ __ \____  / /_  ___  "
print "  / /_/ / / / / /_/ / __ \/ __ \/ _ \ "
print " / ____/ /_/ / _, _/ /_/ / /_/ /  __/ "
print "/_/    \__, /_/ |_|\____/_.___/\___/  "
print "      /____/                   v1.3   "
print "--------------------------------------"	
print "Probe Investigator // dev:localtracker"
print "--------------------------------------"
                                                          

intf = raw_input("Enter the Name of the interface to sniff: ")  # accept input from user for choosing interface
print "\n"
if intf == "":
	print "Please choose a monitor interface"
	intf = raw_input("Enter the Name of the interface to sniff: ")

                                                        
f = open("ProbeLog"+str(today)+str(tf)+".txt","w")	  # create the log file			
                                                          
clients = []						  # define variables
uni = 0
mach = []
manu =[]
                                                          
def phandle(p):						  # our main function
    global uni    
    if p.haslayer(Dot11ProbeReq):                         # check if packet contains a probe request layer
        mac = str(p.addr2)
        if p.haslayer(Dot11Elt):                          # check if information element is present
            if p.ID == 0: 
                ssid = p.info                             # extract ssid
                if ssid not in clients and ssid != "":
                    clients.append(ssid)		  
                    maco = EUI(mac)
		    macf = maco.oui.registration().org    # lookup MAC address against IEEE OUI database for manufacturer
		    print len(clients),mac+" ("+macf+") <--Probing--> "+ssid
		    f.write (str(len(clients))+" "+mac+" ("+macf+") //"+" <--Probing--> "+ssid+"\n")
		    if mac not in mach:
                        mach.append(mac)
                        uni+=1                            # increment unique MAC counter		    	
	 
sniff(iface=intf,prn=phandle, store=0)                    # our sniff function
print ("\n")
print "Unique MACs: ",uni
f.write ("\nUnique MACs: "+str(uni))
f.write ("\nScan performed on: "+str(d)+" at"+str(t))  
f.close()                                                 # close the log file