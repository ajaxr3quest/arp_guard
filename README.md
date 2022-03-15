# ARP Guard
							 
ARP Guard it's a double edge sword. You could use it as a defensive tool to keep en eye on your network, or as an offensive tool to inspect your target's network.
It's a CLI sniffer which sniffs ARP traffic to create its own ARP table. It lets you make and historic of all the hosts that go through your network, as well as tag them.



### Some features are

	-Identify live hosts within the network  
	-Catch ARP spoofing tries or IP changes  
	-Sniff ARP traffic  
	-Generate an historic ARP table of the target network  
	-Sniff the network both actively (with -d or --disc argument) or passively  
	-Import/export function using CSV files  
	-Email alerts when certain events trigger: on new hosts or ARP spoofing tries 
	 

## Getting started

Install **python3** and **pip**.


Install all requirements with:
```
pip install -r requirements.txt
```

Start the program with:
```
python3 arp_guard.py
```


You could start the program with the following arguments:
```
-h, --help            show this help message and exit
-s, --sniff           start the program with the sniffer activated
-d, --disc            start the program launching an ARP discovery
--export filename     export ARP table to a CSV file
--import filename     import ARP table from a CSV file
-ni, --nointeractive  start the program in a non interactive mode
```

### Don't regret later
For using email alerts you will be asked for a valid SMTP email and password. A file with **the provided SMTP credentials will be saved locally in an insecure manner (without proper encryption, just as plaintext)** under config/.
I obviously discourage using your real email in case any breach happens on your system. That said, my wise advice (if you are lazy and don't want to edit the script) is to create a new email and use that one as the sender. 



