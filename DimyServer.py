import socket
import threading
import pickle
import pybloom_live
import logging
import signal
from typing import Tuple

# Set up logging config
logging.basicConfig(level=logging.INFO, format='%(message)s')

HOST = 'localhost'
PORT = 55000

encID = {}
CBF = pybloom_live.BloomFilter(capacity=1000, error_rate=0.001)

def uploadEncID(clientsocket: socket.socket, addr: Tuple[str, int]) -> None:
    global CBF
    logging.info(f"Got a connection from {addr}")
    
    try:
        with clientsocket:
            bytes_data = clientsocket.recv(50000)
            BFtuple = pickle.loads(bytes_data)
            BF = BFtuple[1]
            
            if BFtuple[0] == 'CBF':
                CBF = BF
                clientsocket.send(pickle.dumps('uploaded CBF'))
            else:
                encID[addr[1]] = BF
                intersection = CBF.intersection(BF).bitarray.count()
                logging.info(f'Segment 10: received QBF performing risk analysis {intersection}')
                result = 'Matched' if intersection > 0 else 'Not Matched'
                clientsocket.send(pickle.dumps(('intersection ', result)))
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