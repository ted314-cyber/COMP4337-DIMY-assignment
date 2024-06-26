#!/usr/bin/env python3

import hashlib
import binascii
import threading
import socket
import time
import random
from ecdsa import ECDH, SECP128r1
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

# Global variables for network communication
server = None
client = None
server_url = 'http://127.0.0.1:55000'
print_lock = threading.Lock()  # Global lock for synchronized printing
task_completed = threading.Event()  # Event to synchronize task completion

def safe_print(*args, **kwargs):
    """Thread-safe print function."""
    with print_lock:
        print(*args, **kwargs)

############################## Task 1 ##############################
def generate_ephemeral_id():
    """Task 1: Generates a 16 Byte ephemeral ID using ECDH"""
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()
    ephemeral_id = public_key.to_string('compressed')[1:]
    safe_print("\n------------------> Segment 1 <------------------")
    safe_print(f"Task 1: Generated EphID: {binascii.hexlify(ephemeral_id).decode()}")
    task_completed.set()  # Signal that Task 1 is complete
    return ephemeral_id, ecdh

def generate_hash(ephemeral_id):
    """Generates a SHA-256 hash of the ephemeral ID"""
    return hashlib.sha256(ephemeral_id).hexdigest()

############################## Task 2 ##############################
def generate_shares(ephemeral_id, k=3, n=5):
    """Task 2: Generates n shares of the EphID using k-out-of-n Shamir Secret Sharing"""
    task_completed.wait()  # Wait for Task 1 to complete
    task_completed.clear()  # Clear event for the next task
    shares = Shamir.split(k, n, ephemeral_id)
    safe_print("\n------------------> Segment 2 <------------------")
    safe_print(f"Task 2: Generated {n} shares for EphID:")
    for i, share in enumerate(shares):
        safe_print(f"  Share {i+1}: {share}")
    task_completed.set()  # Signal that Task 2 is complete
    return shares

def ephemeral_id_routine():
    """Thread routine to generate ephemeral ID, its hash, and shares every 15 seconds"""
    while True:
        ephemeral_id, ecdh = generate_ephemeral_id()
        hash_eph_id = generate_hash(ephemeral_id)
        shares = generate_shares(ephemeral_id)
        time.sleep(15)

############################## Task 3 & 3a ##############################
def broadcast_shares():
    """Task 3: Broadcasts shares over UDP with random drops"""
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.bind(("", 44444))

    while True:
        task_completed.wait()  # Wait for Task 2 to complete
        task_completed.clear()  # Clear event for the next task
        ephemeral_id, _ = generate_ephemeral_id()
        shares = generate_shares(ephemeral_id)
        for share in shares:
            safe_print("\n------------------> Segment 3 <------------------")
            safe_print(f"Task 3: Preparing to broadcast Share {share[0]}")
            if random.random() < 0.5:
                safe_print(f"Task 3a: Dropping share {share[0]}")
                continue
            share_bytes = str.encode(f"{share[0]}, {binascii.hexlify(share[1])}")
            server.sendto(share_bytes, ('<broadcast>', 37025))
            safe_print(f"Task 3: Broadcasting share {share[0]}")
            time.sleep(3)
        task_completed.set()  # Signal that Task 3 is complete

############################## Task 4 ##############################
def receive_shares():
    """Receives shares from other devices"""
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37025))

    while True:
        data, _ = client.recvfrom(1024)
        share = data.decode()
        safe_print("\n------------------> Segment 4 <------------------")
        safe_print(f"Task 4: Received share: {share}")

def main():
    ephemeral_id_thread = threading.Thread(target=ephemeral_id_routine, name="EphemeralIDGenerator")
    sender_thread = threading.Thread(target=broadcast_shares, name="ShareBroadcaster")
    receiver_thread = threading.Thread(target=receive_shares, name="ShareReceiver")

    ephemeral_id_thread.start()
    sender_thread.start()
    receiver_thread.start()

    ephemeral_id_thread.join()
    sender_thread.join()
    receiver_thread.join()

if __name__ == "__main__":
    main()
