#!/usr/bin/env python
# import all the needed libraries
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
from netaddr import *
import os
import os.path
import sys
import datetime
import time
from subprocess import *
import argparse

# Colours
R  = '\033[31m' 
W  = '\033[0m'  
O  = '\033[33m' 
G  = '\033[32m'
Y ='\033[93m'


# clear the console
call(["clear"])  

def parse_args():
	parser = argparse.ArgumentParser(description='PyRobe Help')
	parser.add_argument('interface', action="store", help="specify monitor interface (ex. mon0)", default=False)
	parser.add_argument("-l","--log", help="print log file with specified name (ex. -l mylog)")
        return parser.parse_args()
		
def wr_log(mac, ssid, macf):
    	f.write (str(len(clients))+" "+mac+" ("+macf+") //"+" <--Probing--> "+ssid+" "+"// Seen:"+t+"\n")
	
def wr_unimac(uni):
		f.write ("\nUnique devices: "+str(uni))
		f.write ("\nScan performed on: "+str(d)+" at"+str(t))	
		f.close()	
		print G+'Log successfully written.'+W

def checkmac(macaddr):
	global uni
	if macaddr not in clients:
		clients.append(macaddr)
		uni+=1

def get_oui(mac):
	global macf
	maco = EUI(mac)
	macf = maco.oui.registration().org
	return macf

# set date-time parameters                                                          
today = datetime.date.today()				  
d=today.strftime("%d-%b-%Y")
t=time.strftime(" %H:%M:%S")

# print sexy ascii art                                                          
print O+'    ____        ____        __        '+W
print O+'   / __ \__  __/ __ \____  / /_  ___  '+W
print O+'  / /_/ / / / / /_/ / __ \/ __ \/ _ \ '+W
print G+' / ____/ /_/ / _, _/ /_/ / /_/ /  __/ '+W
print G+'/_/    \__, /_/ |_|\____/_.___/\___/  '+W
print G+'      /____/                   '+W+'v1.4'
print O+'--------------------------------------'+W	
print 'Probe Investigator'+O+' // '+W+'dev:localtracker'
print O+'--------------------------------------'+W
print G+'MPS'+W+' = Multiple probes for same SSID'
print G+'MPM'+W+' = Multiple probes from same MAC address\n'
                                                          
# packet handler                                                          
def phandle(p):
    global count
    global dup
    global mpm
    global mps
    											  
    if p.haslayer(Dot11ProbeReq):                         
        if p.haslayer(Dot11Elt):                          
            if p.ID == 0: 
                ssid = p.info
		if ssid != "" and ssid not in net and p.addr2 not in clients:
			count +=1                             		  
                	net.append(ssid)
			get_oui(p.addr2)   
			print str(count)+'>',p.addr2+' ('+G+macf+W+') <--Probing--> '+O+ssid+W
			if args.log:
				wr_log(p.addr2,ssid,macf)
			checkmac(p.addr2)
		elif ssid != "" and ssid in net and p.addr2 not in clients:
			count +=1
			get_oui(p.addr2)   
			print str(count)+'>',p.addr2+' ('+G+macf+W+') <--Probing--> '+O+ssid+W+' < '+Y+'MPS'+W
			if args.log:
				wr_log(p.addr2,ssid,macf)
			checkmac(p.addr2)
			net.append(ssid)
			mps+=1
		elif ssid!= "" and ssid not in net and p.addr2 in clients:
			count +=1
			net.append(ssid)
			get_oui(p.addr2)   
			print str(count)+'>',p.addr2+' ('+G+macf+W+') <--Probing--> '+O+ssid+W+' < '+Y+'MPM'+W
			if args.log:
				wr_log(p.addr2,ssid,macf)
			clients.append(p.addr2)
			mpm+=1
		elif ssid!= "" and ssid in net and p.addr2 in clients and count > 1:
			g1 = (x for x in net if x == ssid)
			g2 = (y for y in clients if y == p.addr2)
			if range(len(net)) > 1 and range(len(clients)) > 1:
				for x in g1:
					for y in g2: 
						dup+=1
			else:
				count +=1
				get_oui(p.addr2)   
				print str(count)+'>',p.addr2+' ('+G+macf+W+') <--Probing--> '+O+ssid+W+' < '+Y+'MPM/MPS'+W
				if args.log:
					wr_log(p.addr2,ssid,macf)
				clients.append(p.addr2)
				net.append(ssid)  	
		    	                          
# main				
if __name__ == "__main__": 
	if os.geteuid():
        	sys.exit(O+'This must be run as root!')
# define variables                                                          
	clients = []						  
	uni = 0
	net = []
	args = parse_args()
	intf = args.interface
	count = 0
	dup = 0
	mpm = 0
	mps = 0

	if not args.log:
            args.log = False
	else:
	    f = open(args.log+".txt","w")

	try:		
		sniff(iface=intf,prn=phandle, store=0)                    
        	print ("\n")
        	print'Unique devices: ',G+str(uni)+W
		print'Multiple probes for same SSID: ',G+str(mps)+W
		print'Multiple probes from same MAC address: ',G+str(mpm)+W
		if args.log:
			wr_unimac(uni)
		elif args.log == False:
			print G+'Log not written!'+W		                                                  
		print G+'Clean exit!'+W
	except Exception as msg:
		print '\n'+R+'Something happened! Exiting!'
        	sys.exit(0)