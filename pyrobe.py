#!/usr/bin/env python
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
# import all the needed libraries


# Colours
R  = '\033[31m' 
W  = '\033[0m'  
O  = '\033[33m' 
G  = '\033[32m'
Y ='\033[93m'


# clear the console
call(["clear"])  

# command line arguments
def parse_args():
	parser = argparse.ArgumentParser(description='PyRobe Help')
	parser.add_argument('interface', action="store", help="specify monitor interface (ex. mon0)", default=False)
	parser.add_argument("-l","--log", help="print log file with specified name (ex. -l mylog)")
        return parser.parse_args()

# write results to log	
def wr_log(mac, ssid, macf):
    	f.write (mac+" ("+macf+") //"+" <--Probing--> "+ssid+" "+"// Seen:"+t+"\n")

# write unique results to log	
def wr_unimac(uni):
		global macf
		f.write ("\n-----------------------------------------------")
		f.write ("\nUnique devices: "+str(uni))
		f.write ("\nUnique networks:"+str(unet))
		f.write ("\nPopular device: "+str(topd))
		f.write ("\nPopular network:"+str(topn))
		f.write ("\nScan performed by PyRobe on:"+str(d)+" at"+str(t))	
		f.close()	
		print G+'Log successfully written.'+W

# check for unique mac address
def checkmac(macaddr):
	global uni
	if macaddr not in clients:
		clients.append(macaddr)
		uni+=1

# check for unique ssid
def checknet(sid):
	global unet
	if sid not in net:
		net.append(sid)
		unet+=1

#get device manufacturer
def get_oui(mac):
	global macf
	maco = EUI(mac)
	macf = maco.oui.registration().org
	return macf

# get our polular devices and networks
def fpop():
	global topd
	global topn
	mpopd = {}
	mpopn = {}
	for (x,y) in obs:
		if x in mpopd:
			mpopd[x] += 1
		else:
			mpopd[x] = 1
		if y in mpopn:
			mpopn[y] += 1
		else:
			mpopn[y] = 1
		

	popud = sorted(mpopd, key = mpopd.get, reverse = True)
	popun = sorted(mpopn, key = mpopn.get, reverse = True)
	topd = popud[:1]
	topn = popun[:1]
	

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
                                                          
# packet handler                                                          
def phandle(p):
    global count
    global vali		 	
    global macf
    global unet
												  
    if p.haslayer(Dot11ProbeReq):                         
        if p.haslayer(Dot11Elt):
	    vali = 0	                          
            if p.ID == 0: 
                ssid = p.info
		if ssid != "":
			for (i,j) in obs:
				if (i,j) != (p.addr2,ssid):
					vali += 1
				else:
					break
			if vali == len(obs):
				obs.append((p.addr2,ssid))
				checkmac(p.addr2)
				checknet(ssid)
				count +=1
				get_oui(p.addr2)
				print str(count)+'>',p.addr2+' ('+G+macf+W+') <--Probing--> '+O+ssid+W
				wr_log(p.addr2,ssid,macf)
					
			else:
				pass
														                  
# main				
if __name__ == "__main__": 
	if os.geteuid():
        	sys.exit(O+'This must be run as root!')

# define variables                                                          
	clients = []
	net = []
	obs = []						  
	uni = 0
	unet = 0
	count = 0
	vali = 0
	args = parse_args()
	intf = args.interface
	
# write temp log even if no l argument specified
	if not args.log:
	    f = open("temp.txt","w")	
            args.log = False
	else:
	    f = open(args.log+".txt","w")

	try:		
		sniff(iface=intf,prn=phandle, store=0)                    
        	print ("\n")
		fpop ()
        	print'Unique devices: ',G+str(uni)+W
		print'Unique networks:',G+str(unet)+W
		print'Popular device: ',G+str(topd)+W
		print'Popular network:',O+str(topn)+W	
		if args.log == False:
			inp = raw_input("Do you want to save a log?(y/n)")
			if inp == 'y':
				inp2 = raw_input("Enter your desired log name: ")
				wr_unimac(uni)
				call(["mv","temp.txt",inp2+".txt"]) 
			elif inp == 'n':
				print G+'Log not written!'+W
				call(["rm","temp.txt"]) 
			else:
				print "Not the right choice. Choose between 'y' <- YES or 'n' <- NO"
		elif args.log:
			wr_unimac(uni)	                                                  
		print G+'Clean exit!'+W
	except Exception,e:
		print '\n'+R+'Something happened! Exiting!'
        	print str(e)