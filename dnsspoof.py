#!/usr/bin/python

##IMPORTS
from scapy.all import *
import argparse

#Program INPUTS:
# - Victim IP
# - Router IP
#0. Get all the inputs
	#Allow attacker to enter:
	#python dnsspoof.py -v 192.168.0.10 -r 192.168.0.1
def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="IP address of victim")
	parser.add_argument("-r", "--routerIP", help="IP address of router")
	return parser.parse_args()
#1. Get all the details in prep for ARP poisoning
	#1A: Get MAC address of victim machine
	#1B: Get MAC address of router
#2. Enable IP forwarding so that packets from victim will be forwarded
	#2A write "1" into /proc/sys/net/ipv4/ip_forward
#3. Perform Arp Poisoning
	#3A Repeatedly send ARP reply's to VICTIM stating that router IP
	# is at THIS MAC addr
	#3B Repeatedly send ARP reply's to ROUTER stating that the victim IP
	# is at THIS MAC
#4. After ARP poisoning has occurred, drop any forwarded DNS packets
	#Firewall rule, disable forwarding of any UDP packets to dport 53 
#5. In a new thread, sniff for DNS queries.
	#5A. Craft DNS answers that whatever has been requested
	#lives at THIS IP.


## Restoring ARP tables so that we don't break shit
	#R1: Broadcast ARP reply to all to tell them that VICTIM is at IP
	#R2: Broadcast ARP reply to all to tellt hem that ROUTER is at IP 

if __name__ == '__main__':
	arguments = parse_arguments()
	victimIP = arguments.victimIP
	routerIP = arguments.routerIP

	print "victimIP is " + victimIP
	print "routerIP is " + routerIP



#Credit to this gu's tutorial:
#http://danmcinerney.org/arp-poisoning-with-python-2/