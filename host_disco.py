from scapy.all import *

ip="0.0.0.0"

def scan(ip):
	rep=sr1(IP(dst=ip)/TCP(flags="S"))
	if rep != None:
		if TCP in rep:
			if rep[TCP].flags == 0x12: #ACK
				print("TCP ok pour " + str(ip))
			elif rep[TCP].flags == 0x14 : #RST/ACK
				print("TCP dead pour " + str(ip))

	rep_icmp=sr1(IP(dst=ip)/ICMP())
	if rep_icmp != None:
		if ICMP in rep_icmp:
			if rep_icmp[ICMP].type == 0:
				print("ICMP ok pour " + str(ip))
			else:
				print("ICMP dead pour " + str(ip))

	rep_udp=sr1(IP(dst=ip)/UDP(),timeout=5)
	if rep_udp != None:
		if ICMP in rep_udp:
			if rep_udp[ICMP].type == 3 and rep_udp[ICMP].code == 3:
				print("UDP dead pour " + str(ip))
			elif rep_udp[ICMP].type == 3 and rep_udp[ICMP].code != 3:
				print("UDP filtre pour " + str(ip))
	else:
		print("UDP ok pour " + str(ip))

scan(ip)
