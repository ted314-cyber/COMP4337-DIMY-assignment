import socket
import random
import time
import pickle
import sys
import os


# Takes in server port, and node number
udp_broadcast_port = 55000
host = '127.0.0.1'

attackerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
attackerSocket.bind((host, 8887)) #no specifications on attacker port.

start_time = time.time()
while time.time() - start_time < 90:

    impersonate_ports = udp_broadcast_port
    msgtuple1 = ('receiverPG', 5, os.urandom(32)) #impersonate receiving 3 shares 
    msgtuple2 = ('senderPub', os.urandom(32), impersonate_ports) 
    #impersonate being a broadcaster, sending back pub key, spoof port
    print('Segment 11-A: sending spoof and flood attack')
    attackerSocket.sendto(pickle.dumps(msgtuple1), (host, udp_broadcast_port))
    attackerSocket.sendto(pickle.dumps(msgtuple2), (host, udp_broadcast_port))
