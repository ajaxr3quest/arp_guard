## Leaving ARP Guard running on the background (Linux users) ##

Install screen

```sudo apt install screen```

Call screen 

```screen```

Open ARP guard in sniffing mode

```python3 arp_guard.py -s```


Press Ctrl-A then Ctrl-D. This will "detach" your screen session but leave your processes running.  
If you want to come back later, log on again and type `screen -r` This will "resume" your screen session, and you can come back to ARP guard.
