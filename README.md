# PyRobe v1.6
##### // dev: localtracker

A simple scapy based utility to scan for probe requests from devices. Resolves MAC address, manufacturer, SSID, signal strength and supports logging data with timestamp. Please submit feature requests that cane extend data functionality.

_So simple it hurts!_

## Requirements

Three things to function properly.

	1. Python 2.x (https://www.python.org/downloads/)
```
doh!
```
	2. Scapy (http://www.secdev.org/projects/scapy/)
```
pip install scapy
``` 
	3. Netaddr (https://github.com/drkjam/netaddr) - MAC OUI lookup support
```
pip install netaddr
``` 
## Usage

You have to specify a monitor interface everytime the script runs (ex:**mon0**). You can use airmon-ng to initantiate a moniter interface. Supposing your wlan interface is wlan1.

```
airmon-ng start wlan1
```
If running the script for the first time, you will have to change permissions. Run-

```
chmod a+x pyrobe.py
```
#### Help output

```
./pyrobe.py -h
    ____        ____        __        
   / __ \__  __/ __ \____  / /_  ___  
  / /_/ / / / / /_/ / __ \/ __ \/ _ \ 
 / ____/ /_/ / _, _/ /_/ / /_/ /  __/ 
/_/    \__, /_/ |_|\____/_.___/\___/  
      /____/                   v1.6
---------------------------------------
Probe Req Harvester // dev:localtracker
---------------------------------------
usage: pyrobe.py [-h] [-l LOG] interface

PyRobe Help

positional arguments:
  interface          specify monitor interface (ex. mon0)

optional arguments:
  -h, --help         show this help message and exit
  -l LOG, --log LOG  print log file with specified name (ex. -l mylog)
```
#### Specifying the monitor interface

```
./pyrobe.py mon0

[*] Trying to sniff on mon0
[+] Connections up! Captured our first probe

[*] Time taken for first resolve: 2 secs!

1>  d0:xx:be:cc:1f:ee [-63dBm] (Samsung Electro Mechanics co.,LTD.) <--Probing--> Wifi-X
^C
[-] Sniffing stopped on mon0! Connections down!

Popular devices : ['d0:xx:be:cc:1f:ee']
Popular networks: ['Wifi-X']
Closest device  : ('d0:xx:be:cc:1f:ee', -63)
Unique devices  : 1
Unique networks : 1
Probes Sniffed  : 7
Time since init : 0h:0m:8s

[!] Warning
-----------
Do you want to save a log?(y/n) n
Log not written!
Clean exit!
```
#### Logging data

By default, the script will log data to a temporary text file. Specifying the "-l" option with the filename while initializing the script will output a log file with the desired filename that contains all recorded data plus the last seen time for each device. If the log file of the same name already exists, PyRobe will overwrite the file. If, in the middle of your scan, you decide that you should have logged data then you still can, after your are done scanning, by pressing 'Ctrl+c' once.

```
./pyrobe.py mon0 -l mylog

[*] Trying to sniff on mon0
[+] Connections up! Captured our first probe

[*] Time taken for first resolve: 2 secs!

1>  d0:xx:be:cc:1f:ee [-63dBm] (Samsung Electro Mechanics co.,LTD.) <--Probing--> Wifi-X
^C
[-] Sniffing stopped on mon0! Connections down!

Popular devices : ['d0:xx:be:cc:1f:ee']
Popular networks: ['Wifi-X']
Closest device  : ('d0:xx:be:cc:1f:ee', -63)
Unique devices  : 1
Unique networks : 1
Probes Sniffed  : 7
Time since init : 0h:0m:8s
Log successfully written.
Clean exit!
```
#### Reading statictics

At the end of your scan, you will be presented with data that can increase your chances of success and help determine potential target devices and networks. The data can used for MITM attacks and passive surviellance. The closest device shown can also be your own device so be sure to turn off wifi on your own devices if particularly looking to find devices closeby.

## The ideology behind this.

It the end, you can identify multiple targets and networks and use the data for reconnaissance purposes. There are endless ways to play with the data collected and open opportunities, if you know how.  

You can capture more probe requests by:

	1. Run pyrobe.py
	2. Open a channel hopping deauth utility like "wifijammer.py" and let it rip.
	3. A ton of probes!

By studying these probe requests and/or querying them against **wigle.net** for known SSID locations, you can create a character/target profile that can help determine the next step. Again, this is just one of the things that you can do.

_I am not liable as to how this script/information would be used._

#### To-do

1. Add ability to store results in a sqlite database
2. Query from database
3. Resolve device names (ex: Gio's iPhone 5) -- can someone shed some light on how to achieve this?
4. Resolve SSID's to geographical co-ordinates.
5. Make it a modular suite.