import os
os.environ['http_proxy'] = ''

import time
import socket

os.system('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')


s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.connect(("2001:db8:0:1:d1:89ec:891:eba3", 1234))

while True:
	print(s.recv(32))
	time.sleep(1)

s.close()
