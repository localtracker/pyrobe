# PyRobe

A simple scapy based utility to scan for probe requests from devices.

No installation is needed as far as the script is concerned. But you do need to install scapy before you run this script.

You have to specify a monitor interface everytime the script runs (ex: mon0).
	

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


1 ff:ab:ff:98:ff:b3 <--Probing--> Wifi-xx

^C

Unique MACs:  1


The script outputs a log with the recoded MAC addresses and SSID's being probed in the same location the script was run from. At the end you can find information such as unique MAC addresses in the list and scan time and date.

You can capture more probe requests by:

  1. Run pyrobe.py
  2. Open a channel hopping deauth utility like "wifijammer.py" and let it till the list stops updating.
  3. Tons more probe requests!

So simple it hurts!
