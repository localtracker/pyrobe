# PyRobe

A simple scapy based utility to scan for probe requests from devices.

_So simple it hurts!_

# Requirements

Three things to function properly.

	1. Python 2.x (https://www.python.org/downloads/)
	2. Scapy (http://www.secdev.org/projects/scapy/)

```
pip install scapy
``` 
	3. Netaddr (https://github.com/drkjam/netaddr)
```
pip install netaddr
``` 
# Usage

You have to specify a monitor interface everytime the script runs (ex: _mon0_). You can use airmon-ng for this purpose. Supposing your wlan interface is wlan1.

```
airmon-ng start wlan1
```
Navigate to the folder where you downloaded pyrobe and open the terminal from there. Run-

```
chmod a+x pyrobe.py
```
Then simply fire up the script by

```
./pyrobe.py
    ____        ____        __        
   / __ \__  __/ __ \____  / /_  ___  
  / /_/ / / / / /_/ / __ \/ __ \/ _ \ 
 / ____/ /_/ / _, _/ /_/ / /_/ /  __/ 
/_/    \__, /_/ |_|\____/_.___/\___/  
      /____/                          
--------------------------------------
Probe Investigator // dev:localtracker
--------------------------------------
Enter the Name of the interface to sniff: mon0


1 ff:bb:ff:98:ff:b3 (Intel Corporate) <--Probing--> Wifi-xx

^C

Unique MACs:  1
```
The script outputs a log with the recoded MAC addresses and SSID's being probed in the same location the script was run from.

# The Idea

It the end, you can find information such as unique MAC addresses in the list and scan time and date.

You can capture more probe requests by:

	1. Run pyrobe.py
	2. Open a channel hopping deauth utility like "wifijammer.py" and let it rip till the list stops updating.
	3. Tons more probe requests!

By studying these probe requests and querying them against **wigle.net** for known SSID locations, you can find out where your target has been and other useful information.

_I am not liable as to how this script/information would be used._