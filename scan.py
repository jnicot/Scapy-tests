from scapy.all import *
#176.135.82.191
ip="176.135.82.191"
port=53

def ackScan(ip,port):
	#dport = dest Port
	rep = sr1(IP(dst=ip)/TCP(dport=port,flags="S"))
	if rep != None:
		if rep[TCP].flags == 0x12: #ACK
			print("ACK port nb "+ str(port) +" for " + str(ip))
		elif rep[TCP].flags == 0x14: #RST/ACK
			ret = -1
			print("RST/ACK port nb "+ str(port) +" for " + str(ip))
	else:
		print("ko")	
				
#a revoir, refaire des tests en etant sur des ports ouverts/fermes
def finScan(ip,port):
	rep=sr1(IP(dst=ip)/TCP(dport=port,flags="F"),timeout=5)
	if(rep != None):
		if(rep[TCP].flags == 0x04): #RST/ACK
			print("RST port nb" + str(port))
		elif rep[ICMP].type == 3:
			print("ICMP response for port nb" + str())
	else:
		print("No response, port opened")

#pas de reponse si port ferme, cause : srv ?
def xmasScan(ip,port):
	rep=sr1(IP(dst=ip)/TCP(dport=port,flags="FPU"),timeout=5)
	if rep != None:
		if rep[TCP].flags == 0x14:
			print("Port" + str() + "closed")
		elif rep[ICMP].type == 3:
			print("Port" + str() + "filtered")
	else:
		print("Port opened")

#pas de reponse si port ferme, cause : srv ?
def nullScan(ip,port):
	rep=sr1(IP(dst=ip)/TCP(dport=port,flags=""),timeout=5)
	if(rep != None):
		if(rep[TCP].flags == 0x14):
			print("Port" + str() + "closed")
		elif(rep[ICMP].type == 3):
			print("Port" + str() + "filtered")
	else:
		print("Port opened")

#
def ackScan(ip,port):
#ACK scan, utile pour savoir s'il y a un firewall qui filtre sur ce port
	rep=sr1(IP(dst=ip)/TCP(dport=port,flags="A"),timeout=5)
	if(rep != None):
		if(rep[TCP].flags == 0x04):
				print("Port" + str() + "RST/ACK response")
		elif(rep[ICMP].type == 3):
				print("Port" + str() + "ICMP response")
	else:
			print("Port filtered")

#A manier avec precaution, pas toujours pertinent
def udpScan(ip,port):
#UDP scan
	rep=sr1(IP(dst=ip)/UDP(dport=port),timeout=5)
	if(rep != None):
		if(UDP in rep):
			print("Port" + str() + " opened")
		elif(rep[ICMP].type == 3 and rep[ICMP].code == 3):
			print("Port" + str() + " ferme")
		elif(rep[ICMP].type == 3 and rep[ICMP].code != 3):
			print("Port" + str() + " filtre")
	else:
		print("Port opened ou filtered")

udpScan(ip,port)