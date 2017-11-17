import socket

#create an INET, STREAMing socket
s = socket.socket(
    socket.AF_INET6, socket.SOCK_STREAM)
#now connect to the web server on port 80
# - the normal http port
s.connect(("2001:db8:0:1:d1:89ec:891:eba3", 1234))

while True:
	pass
