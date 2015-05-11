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
# imported all the needed libraries

# resize the console window
sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=50, cols=110))

# clear the console
call(["clear"])

# Colours
R  = '\033[31m' 
W  = '\033[0m'  
O  = '\033[33m' 
G  = '\033[32m'
Y ='\033[93m'

# set date-time parameters                                                          
today = datetime.date.today()				  
t=time.strftime(" %H:%M:%S")
print "Started on "+today.strftime("%d-%b-%Y")+" at"+time.strftime(" %H:%M:%S") 

# print sexy ascii art                                                          
print O+'    ____        ____        __        '+W
print O+'   / __ \__  __/ __ \____  / /_  ___  '+W
print O+'  / /_/ / / / / /_/ / __ \/ __ \/ _ \ '+W
print G+' / ____/ /_/ / _, _/ /_/ / /_/ /  __/ '+W
print G+'/_/    \__, /_/ |_|\____/_.___/\___/  '+W
print G+'      /____/                   '+W+'v1.6'
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
	f.write ("\n-----------------------------------------------")
	f.write ("\nClosest device: "+str(cldev))
	f.write ("\nPopular device: "+str(topd))
	f.write ("\nPopular network:"+str(topn))
	f.write ("\nUnique devices: "+str(len(clients)))
	f.write ("\nUnique networks:"+str(len(net)))
	f.write ("\nScan performed by PyRobe on: "+today.strftime("%d-%b-%Y")+" at"+time.strftime(" %H:%M:%S"))	
	f.close()	
	print G+'Log successfully written.'+W

# check for unique mac address
def checkmac(macaddr):
	global sig
	if macaddr not in clients:
		clients.append(macaddr)
		cld.append((macaddr,sig))

# check for unique ssid
def checknet(sid):
	if sid not in net:
		net.append(sid)

#get device manufacturer
def get_oui(mac):
	global macf
	maco = EUI(mac)
	oui = maco.oui
	macf = oui.registration(0).org
	return macf
	
# get probable targets
def fpop():
	global topd, topn, cldev
	clo = []
	mpopd, mpopn = {}, {}
	sign = -100
	st = ""
	for (x,y) in obs:
		if x in mpopd:
			mpopd[x] += 1
		else:
			mpopd[x] = 1
		if y in mpopn:
			mpopn[y] += 1
		else:
			mpopn[y] = 1
	for (m,s) in cld:
		if sign < s:
			sign = s
			st = (m,sign)
	clo.append(st)
	popud = sorted(mpopd, key = mpopd.get, reverse = True)
	popun = sorted(mpopn, key = mpopn.get, reverse = True)
	if len(popud) > 5:
		topd = popud[:2]
	else:
		topd = popud[:1]
	topn = popun[:1]
	cldev = clo[0]

# get time since init
def get_time_elapsed(to,fro):
	global t3, hours, minutes, seconds
	t3 = to-fro
	seco = t3.seconds
	hours = seco // 3600
	seco = seco - (seco*hours)
	minutes = seco // 60
	seconds = seco - (minutes*60)

# check if log needed
def check_log():
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

# get statistics for our scan
def get_stats():
	print'\nPopular devices :',O+str(topd)+W
	print'Popular networks:',O+str(topn)+W
	print'Closest device  :',O+str(cldev)+W
        print'Unique devices  :',G+str(len(clients))+W
	print'Unique networks :',G+str(len(net))+W
	print'Probes Sniffed  :',G+str(pc)+W
	print'Time since init :',G+str(hours)+'h:'+str(minutes)+'m:'+str(seconds)+'s'+W
	
# This completes all the helper functions, now on to the main.
                                                          
# the packet handler                                                          
def phandle(p):
	global count, vali, pc, sig									  
    	if p.haslayer(Dot11ProbeReq):
		if pc == 0:
			print O+'[+]'+W+' Connections up! Captured our first probe\n'	                      
        	if p.haslayer(Dot11Elt):
			pc +=1
	    		vali = 0	                          
            		if p.ID == 0: 
                		ssid = p.info
				if ssid != "":
					t2 = datetime.datetime.now()
					for (i,j) in obs:
						if (i,j) != (p.addr2,ssid):
							vali += 1
						else:
							break
					if vali == len(obs):
						sig = -(256-ord(p.notdecoded[-4:-3]))
						obs.append((p.addr2,ssid))
						checkmac(p.addr2)
						checknet(ssid)
						count +=1
						get_oui(p.addr2)
						if count == 1:
							t3 = t2-t1
							print O+'[*]'+W+' Time taken for first resolve: '+str(t3.seconds)+' secs!\n'
							print str(count)+'> ',p.addr2+' ['+O+str(sig)+'dBm'+W+'] ('+G+macf+W+') <--Probing--> '+O+ssid+W
						elif count < 10:
							print str(count)+'> ',p.addr2+' ['+O+str(sig)+'dBm'+W+'] ('+G+macf+W+') <--Probing--> '+O+ssid+W
						else:
							print str(count)+'>',p.addr2+' ['+O+str(sig)+'dBm'+W+'] ('+G+macf+W+') <--Probing--> '+O+ssid+W
						wr_log(p.addr2,ssid,macf)	
					else:
						pass
														                  
# the main codeblock				
if __name__ == "__main__": 
	if os.geteuid():
        	sys.exit('\n'+O+'[!]'+W+' This must be run as root!\n')

# define variables                                                          
	clients, net, obs, cld = [], [], [], []
	count, vali, pc = 0, 0, 0
	sig = -300						  
	args = parse_args()
	intf = args.interface
	
# write temp log for backup even if no argument specified
	if not args.log:
	    f = open("temp.pyr","w")	
            args.log = False
	else:
	    f = open(args.log+".txt","w")

	try:	
		print O+'[*]'+W+' Trying to sniff on '+intf
		t1 = datetime.datetime.now()
		sniff(iface=intf,prn=phandle, store=0)
		t4 = datetime.datetime.now()
		print O+'\n[-]'+W+' Sniffing stopped on '+intf+'! Connections down!'                   
		fpop ()
		get_time_elapsed(t4,t1)
		get_stats()	
		check_log()	                                                  
		print G+'Clean exit!'+W
	except Exception,e:
		print '\n'+O+'[!]'+W+' Error! Something happened!\n'
        	print str(e)
	except KeyboardInterrupt:
		print '\n'
        	call(["rm","temp.pyr"])