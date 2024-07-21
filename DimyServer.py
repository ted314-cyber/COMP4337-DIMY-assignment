import socket
import threading
import pickle
import logging
import signal
import bitarray
import mmh3
import time
from typing import Tuple

# Set up logging config
logging.basicConfig(level=logging.INFO, format='%(message)s')

HOST = 'localhost'
PORT = 55000

encID = {}

class BloomFilter:
    def __init__(self, size=10000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)
        self.dbf_start_time = time.time()

    def add(self, item):
        if isinstance(item, str):
            item = item.encode()
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            self.bit_array[digest] = 1

    def check(self, item):
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            if self.bit_array[digest] == 0:
                return False
        return True

CBFs = []

def uploadEncID(clientsocket: socket.socket, addr: Tuple[str, int]) -> None:
    global CBFs
    logging.info(f"Got a connection from {addr}")
    
    try:
        with clientsocket:
            bytes_data = clientsocket.recv(50000)
            BF = pickle.loads(bytes_data)

            if isinstance(BF, tuple) and BF[0] == 'CBF':
                CBFs.append(BF[1])
                clientsocket.send(pickle.dumps('uploaded CBF'))
                logging.info(f'Segment 10: received and stored new CBF')
            else:
                encID[addr[1]] = BF
                matched = False
                for cbf in CBFs:
                    intersection = (cbf.bit_array & BF.bit_array).count()
                    logging.info(f'Segment 10: performing risk analysis, intersection: {intersection}')
                    if intersection > 0:
                        matched = True
                        break
                result = 'Matched' if matched else 'Not Matched'
                clientsocket.send(pickle.dumps(('Result', result)))
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")

# Shutdown handler
def shutdown(signal, frame):
    logging.info("Shutting down...")
    serversocket.close()
    exit(0)

signal.signal(signal.SIGINT, shutdown)

# Main server loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
    serversocket.bind((HOST, PORT))
    serversocket.listen(5)
    logging.info(f'Server listening on {HOST}:{PORT}')
    
    while True:  # Infinite loop to accept connections  
        logging.info('Waiting for connection')
        try:
            clientsocket, addr = serversocket.accept()
            threading.Thread(target=uploadEncID, args=(clientsocket, addr)).start()
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

logging.info("Server shutting down")