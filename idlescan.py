from scapy.all import *

srv_ip="176.135.82.191"
smurf_ip="192.168.1.24"
my_ip="192.168.1.69"

#To retrieve IPID of the neighbor
rep=sr1(IP(dst=smurf_ip)/TCP(flags="A",dport=8008))
print(rep)
ipid=rep[IP].id
print("ipid"+str(ipid))

#Send an Syn request as if i am the neighbor
repSrv=send(IP(src=smurf_ip,dst=srv_ip)/TCP(flags="S",sport=5000,dport=80))

rep2=sr1(IP(dst=smurf_ip)/TCP(flags="A",dport=8008))
ipid2=rep2[IP].id
print(ipid2)

#if srv_ip send SYN+ACK, smurf ipid+=2 : socket opened
#if srv_ip send RST, smurf ipid+=1 : socket closed
