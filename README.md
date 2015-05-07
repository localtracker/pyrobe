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
      /____/                   v1.4
--------------------------------------
Probe Investigator // dev:localtracker
--------------------------------------
MPS = Multiple probes for same SSID
MPM = Multiple probes from same MAC address

usage: pyrobe.py [-h] [-l LOG] interface

PyRobe Help

positional arguments:
  interface          specify monitor interface (ex. mon0)

optional arguments:
  -h, --help         show this help message and exit
  -l LOG, --log LOG  print log file with specified name (ex. -l mylog)
```
Specify the monitor interface and off you go!

```
./pyrobe.py mon0

1 ff:bb:ff:98:ff:b3 (Intel Corporate) <--Probing--> Wifi-xx

^C

Unique devices:  1
Multiple probes for same SSID:  0
Multiple probes from same MAC address:  0
Log not written!
Clean exit!
```
By default, the script does not log any data. Specifying the "-l" option with the filename while initializing will output a log file that contains all recorded data plus the last seen time each device. If the log file of the same name already exists, PyRobe will overwrite the file.

```
./pyrobe.py mon0 -l mylog

1 ff:bb:ff:98:ff:b3 (Intel Corporate) <--Probing--> Wifi-xx

^C

Unique devices:  1
Multiple probes for same SSID:  0
Multiple probes from same MAC address:  0
Log successfully written.
Clean exit!
```

# The Idea

It the end, you can find information such as unique MAC addresses in the list and scan time and date.

You can capture more probe requests by:

	1. Run pyrobe.py
	2. Open a channel hopping deauth utility like "wifijammer.py" and let it rip.
	3. Tons more probe requests!

By studying these probe requests and/or querying them against **wigle.net** for known SSID locations, you can create a character/target profile that can help determine the next step.

_I am not liable as to how this script/information would be used._