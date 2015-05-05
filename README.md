# PyRobe

A simple scapy based utility to scan for probe requests from devices.

_So simple it hurts!_

# Requirements

Three things to function properly.

	1. Python 2.x (https://www.python.org/downloads/)

```
doh!
```
	2. Scapy (http://www.secdev.org/projects/scapy/)

```
pip install scapy
``` 
	3. Netaddr (https://github.com/drkjam/netaddr) - To resolve MAC address to manufacturers
```
pip install netaddr
```
 
# Usage

You have to specify a monitor interface everytime the script runs (ex:**mon0**). You can use airmon-ng to initantiate a moniter interface. Supposing your wlan interface is wlan1.

```
airmon-ng start wlan1
```
If running the script for the first time, you will have to change permissions. Run-

```
chmod a+x pyrobe.py
```
Help output from PyRobe..

```
./pyrobe.py -h
    ____        ____        __        
   / __ \__  __/ __ \____  / /_  ___  
  / /_/ / / / / /_/ / __ \/ __ \/ _ \ 
 / ____/ /_/ / _, _/ /_/ / /_/ /  __/ 
/_/    \__, /_/ |_|\____/_.___/\___/  
      /____/                   v1.3   
--------------------------------------
Probe Investigator // dev:localtracker
--------------------------------------
usage: pyrobe.py [-h] [-l] interface

PyRobe Help

positional arguments:
  interface   specify interface (ex. mon0)

optional arguments:
  -h, --help  show this help message and exit
  -l, --log   print log file

```
Specify the monitor interface and off you go!

```
./pyrobe.py mon0

1 ff:bb:ff:98:ff:b3 (Intel Corporate) <--Probing--> Wifi-xx

^C

Unique MACs:  1
Successfully Exited! No log file written.
```
By default, the script does not log any data. Specifying the "-l" option while initializing will output a log file that contains all recorded data.
```
./pyrobe.py mon0 -l

1 ff:bb:ff:98:ff:b3 (Intel Corporate) <--Probing--> Wifi-xx

^C

Unique MACs:  1
Log successfully written. Exiting!
```

# The Idea

It the end, you can find information such as unique MAC addresses in the list and scan time and date.

You can capture more probe requests by:

	1. Run pyrobe.py
	2. Open a channel hopping deauth utility like "wifijammer.py" and let it rip.
	3. Tons more probe requests!

By studying these probe requests and querying them against **wigle.net** for known SSID locations, you can use these findings to create a character profile.

_I am not liable as to how this script/information would be used._