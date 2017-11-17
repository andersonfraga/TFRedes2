# server.py 
import socket                                         
import time
import os
os.system("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")

# create a socket object
serversocket = socket.socket(
	        socket.AF_INET6, socket.SOCK_STREAM) 

# get local machine name
host = ""                          

port = 1234                                           

# bind to the port
serversocket.bind((host, port))                                  

# queue up to 5 requests
serversocket.listen(5)                                           
clientsocket,addr = serversocket.accept()  
print("Got a connection from %s" % str(addr))
while True:
    # establish a connection   	
    currentTime = time.ctime(time.time())
    clientsocket.send(currentTime.encode('ascii'))
    print(currentTime)
    time.sleep(1)



clientsocket.close()
