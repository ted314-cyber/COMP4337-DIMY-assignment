#!/usr/bin/env python3

import hashlib
import binascii
import threading
import socket
import time
import random
import queue
from ecdsa import ECDH, SECP128r1
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

# Global variables for network communication
server_url = "http://127.0.0.1:55000"
output_queue = queue.Queue()  # Queue for thread-safe print operations
share_queue = queue.Queue()  # Queue to hold the shares for broadcast
broadcast_ready = (
    threading.Event()
)  # Event to synchronize the generation and broadcasting of shares
received_shares = {}  # Dictionary to track received shares


def safe_print(*args, **kwargs):
    """Enqueue messages to be printed in the order they were called."""
    message = " ".join(map(str, args))
    output_queue.put(message)


def print_manager(stop_event):
    """Manage the printing from the queue in a single thread."""
    while not stop_event.is_set() or not output_queue.empty():
        try:
            message = output_queue.get(
                timeout=0.1
            )  # Timeout to check for stop_event regularly
            print(message)
        except queue.Empty:
            continue


############################## Task 1 ##############################
# Segment 1: Show the generation of the EphID at the client nodes.
def generate_ephemeral_id():
    """Generates a 16 Byte ephemeral ID using ECDH"""
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()
    ephemeral_id = public_key.to_string("compressed")[1:]
    safe_print("\n------------------> Segment 1 <------------------")
    safe_print("Task 1: Generated EphID:", binascii.hexlify(ephemeral_id).decode())
    return ephemeral_id, ecdh


def generate_hash(ephemeral_id):
    """Generates a SHA-256 hash of the ephemeral ID"""
    return hashlib.sha256(ephemeral_id).hexdigest()


############################## Task 2 ##############################
def generate_shares(ephemeral_id, k=3, n=5):
    """Generates n shares of the EphID using k-out-of-n Shamir Secret Sharing"""
    shares = Shamir.split(k, n, ephemeral_id)
    safe_print("\n------------------> Segment 2 <------------------")
    safe_print("Task 2: Generated", n, "shares for EphID:")
    safe_print(
        "Ephemeral_id used in this segment:", binascii.hexlify(ephemeral_id).decode()
    )
    for i, share in enumerate(shares):
        share_hex = binascii.hexlify(share[1]).decode()
        safe_print(f"  Share {i + 1} : ({share[0]}, {share_hex})")
    return shares


def ephemeral_id_routine():
    """Routine to periodically generate ephemeral IDs and their shares."""
    while True:
        broadcast_ready.wait()  # Ensure synchronization with broadcasting
        ephemeral_id, _ = generate_ephemeral_id()
        shares = generate_shares(ephemeral_id)
        share_queue.put(shares)  # Put the generated shares into the queue
        broadcast_ready.clear()  # Reset the event until shares are broadcasted
        time.sleep(15)


############################## Task 3 ##############################
# Segment 3-A: Show the sending of the shares @ 1 share per 3 seconds over UDP while incorporating the drop mechanism.
# Segment 3-B: Show the receiving of shares broadcast by the other nodes.
# Segment 3-C: Show that you are keeping track of number of shares received for each EphID. Discard if you receive less than k shares.
class ShareManager:
    def __init__(self):
        self.server_socket = self.setup_server_socket()
        self.client_socket = self.setup_client_socket()
        self.start_listening_thread()

    def setup_server_socket(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        server.bind(("", 44444))
        return server

    def setup_client_socket(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.bind(("", 37025))
        return client

    def broadcast_shares(self):
        """Broadcasts shares over UDP with random drops."""
        while True:
            broadcast_ready.set()  # Signal readiness to generate new shares
            shares = share_queue.get()  # Get shares from the queue
            ephid_hash = generate_hash(shares[0][1])  # Hash of the first share (full EphID)
            for share in shares:
                share_data = f"{ephid_hash},{share[0]},{binascii.hexlify(share[1]).decode()}"
                safe_print("\n------------------> Segment 3 <------------------")
                safe_print(f"Task 3: Preparing to broadcast Share {share[0]} with data {share_data}")
                if random.random() < 0.5:
                    safe_print("Task 3a: Dropping share", share[0])
                    continue
                self.server_socket.sendto(share_data.encode(), ("<broadcast>", 37025))
                safe_print("Task 3: Broadcasting share", share[0])
                time.sleep(3)

    def start_listening_thread(self):
        threading.Thread(
            target=self.listen_for_shares, name="ListenThread", daemon=True
        ).start()

    def listen_for_shares(self):
        """Listens for shares and processes them."""
        while True:
            try:
                data, _ = self.client_socket.recvfrom(1024)
                data = data.decode().strip()
                ephid_hash, share_num, share_data = data.split(',')
                share_num = int(share_num)
                share_data = binascii.unhexlify(share_data)

                if ephid_hash not in received_shares:
                    received_shares[ephid_hash] = []
                received_shares[ephid_hash].append((share_num, share_data))

                safe_print(f"Task 3b: Received share {share_num} for hash {ephid_hash}")
                safe_print(f"Task 3c: Total shares received for hash {ephid_hash}: {len(received_shares[ephid_hash])}")

                if len(received_shares[ephid_hash]) < 3:
                    safe_print(f"Not enough shares yet for hash {ephid_hash}. Continuing to collect.")
                else:
                    safe_print(f"Collected enough shares for hash {ephid_hash}. Ready for reconstruction.")

            except Exception as e:
                safe_print(f"Error processing received share: {str(e)}")

    def start(self):
        threading.Thread(
            target=self.broadcast_shares, name="BroadcastThread", daemon=True
        ).start()

def main():
    stop_printing = threading.Event()
    print_thread = threading.Thread(target=print_manager, args=(stop_printing,))
    print_thread.start()

    ephemeral_id_thread = threading.Thread(
        target=ephemeral_id_routine, name="EphemeralIDGenerator"
    )
    ephemeral_id_thread.start()

    manager = ShareManager()
    manager.start()

    try:
        ephemeral_id_thread.join()
    except KeyboardInterrupt:
        stop_printing.set()

    output_queue.put("STOP")
    print_thread.join()


if __name__ == "__main__":
    main()
