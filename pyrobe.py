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

# set date-time parameters                                                          
today = datetime.date.today()				  
d=today.strftime("%d-%b-%Y")
t=time.strftime(" %H:%M:%S")

# clear the console
call(["clear"])

# print sexy ascii art                                                          
print O+'    ____        ____        __        '+W
print O+'   / __ \__  __/ __ \____  / /_  ___  '+W
print O+'  / /_/ / / / / /_/ / __ \/ __ \/ _ \ '+W
print G+' / ____/ /_/ / _, _/ /_/ / /_/ /  __/ '+W
print G+'/_/    \__, /_/ |_|\____/_.___/\___/  '+W
print G+'      /____/                   '+W+'v1.5'
print O+'---------------------------------------'+W	
print 'Probe Req Harvester'+O+' // '+W+'dev:localtracker'
print O+'---------------------------------------'+W  

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
def wr_unimac():
	global macf
	f.write ("\n-----------------------------------------------")
	f.write ("\nPopular device: "+str(topd))
	f.write ("\nPopular network:"+str(topn))
	f.write ("\nUnique devices: "+str(len(clients)))
	f.write ("\nUnique networks:"+str(len(net)))
	f.write ("\nScan performed by PyRobe on:"+str(d)+" at"+str(t))	
	f.close()	
	print G+'Log successfully written.'+W

# check for unique mac address
def checkmac(macaddr):
	if macaddr not in clients:
		clients.append(macaddr)

# check for unique ssid
def checknet(sid):
	if sid not in net:
		net.append(sid)

#get device manufacturer
def get_oui(mac):
	global macf
	maco = EUI(mac)
	macf = maco.oui.registration().org
	return macf
	
# get our polular devices and networks
def fpop():
	global topd, topn
	mpopd, mpopn = {}, {}
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
	topd = popud[:2]
	topn = popun[:2]
	
# This completes all the helper functions, now on to the main.
                                                          
# the packet handler                                                          
def phandle(p):
	global count, vali, pc									  
    	if p.haslayer(Dot11ProbeReq):
		if pc == 0:
			print O+'[+]'+W+' Connections up! Captured our first probe!\n'                         
        	if p.haslayer(Dot11Elt):
			pc +=1
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
														                  
# the main codeblock				
if __name__ == "__main__": 
	if os.geteuid():
        	sys.exit('\n'+O+'[!]'+W+' This must be run as root!\n')

# define variables                                                          
	clients, net, obs = [], [], []
	count, vali, pc = 0, 0, 0						  
	args = parse_args()
	intf = args.interface
	
# write temp log for backup even if no argument specified
	if not args.log:
	    f = open("temp.pyr","w")	
            args.log = False
	else:
	    f = open(args.log+".txt","w")

	try:	
		print O+'[*]'+W+' Trying sniffing on '+intf+'!'
		sniff(iface=intf,prn=phandle, store=0)
		print O+'\n[-]'+W+' Sniffing stopped on '+intf+'! Connections down!'                   
		fpop ()
		print "\n"
		print'Popular devices :',O+str(topd)+W
		print'Popular networks:',O+str(topn)+W
        	print'Unique devices  :',G+str(len(clients))+W
		print'Unique networks :',G+str(len(net))+W
		print'Probes Sniffed  :',G+str(pc)+W	
		if args.log == False:
			print '\n'+O+'[!]'+W+' Warning'
			print '-----------'
			inp = raw_input("Do you want to save a log?(y/n) ")
			if inp == 'y':
				inp2 = raw_input("Enter your desired log name: ")
				wr_unimac()
				call(["mv","temp.pyr",inp2+".txt"]) 
			elif inp == 'n':
				print G+'Log not written!'+W
				call(["rm","temp.pyr"]) 
			else:
				call(["rm","temp.pyr"])
				print "Not the right choice. Choose between 'y' <- YES or 'n' <- NO"
		elif args.log:
			wr_unimac()	                                                  
		print G+'Clean exit!'+W
	except Exception,e:
		call(["rm","temp.pyr"])
		print '\n'+O+'[!]'+W+' Error! Something happened!\n'
        	print str(e)
	except KeyboardInterrupt:
		print '\n'
        	call(["rm","temp.pyr"])