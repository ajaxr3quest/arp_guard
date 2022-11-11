#!/bin/sh
#mata tots els screens
pkill screen
#obra un nou screen amb arp_guard
screen -d -m python3 /opt/arp_guard/arp_guard.py -s -d
