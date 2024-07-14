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
import bitarray
import mmh3

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

# Global variables for network communication
server_url = "http://127.0.0.1:55000"
output_queue = queue.Queue()  # Queue for thread-safe print operations

def safe_print(*args, **kwargs):
    """Enqueue messages to be printed in the order they were called."""
    message = " ".join(map(str, args))
    output_queue.put(message)

def print_manager(stop_event):
    """Manage the printing from the queue in a single thread."""
    while not stop_event.is_set() or not output_queue.empty():
        try:
            message = output_queue.get(timeout=0.5)  # Timeout to check for stop_event regularly
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
    safe_print("Hash:", hashlib.sha256(ephemeral_id).hexdigest())
    return hashlib.sha256(ephemeral_id).hexdigest()

############################## Task 2 ##############################
# Segment 2: Show that 5 shares of the EphIDs are generated at each node
def generate_shares(ephemeral_id, k=3, n=5):
    """Generates n shares of the EphID using k-out-of-n Shamir Secret Sharing"""
    shares = Shamir.split(k, n, ephemeral_id)
    safe_print("\n------------------> Segment 2 <------------------")
    safe_print("Task 2: Generated", n, "shares for EphID:")
    safe_print("Ephemeral_id used in this segment:", binascii.hexlify(ephemeral_id).decode())
    for i, share in enumerate(shares):
        share_hex = binascii.hexlify(share[1]).decode()
        safe_print(f"  Share {i + 1} : ({share[0]}, {share_hex})")
    return shares

def ephemeral_id_routine():
    """Routine to periodically generate ephemeral IDs and their shares."""
    while True:
        ephemeral_id, ecdh = generate_ephemeral_id()
        hash_eph_id = generate_hash(ephemeral_id)
        shares = generate_shares(ephemeral_id)
        time.sleep(15)  # Sleep for 15 seconds before generating a new ID

############################## Task 3 ##############################
# Segment 3-A: Show the sending of the shares @ 1 share per 3 seconds over UDP while incorporating the drop mechanism.
# Segment 3-B: Show the receiving of shares broadcast by the other nodes.
# Segment 3-C: Show that you are keeping track of number of shares received for each EphID. Discard if you receive less than k shares.
class ShareManager:
    def __init__(self):
        self.server_socket = self.setup_server_socket()
        self.client_socket = self.setup_client_socket()
        self.encid_verification_socket = self.setup_encid_verification_socket()
        self.received_shares = {}
        self.ecdh = ECDH(curve=SECP128r1)
        self.ecdh.generate_private_key()
        self.computed_encID = None
        self.current_ephid = None
        self.current_shares = None
        self.dbf = BloomFilter()
        self.dbf_list = []
        self.dbf_start_time = time.time()
        self.dbf_max_age = 540  # 9 minutes in seconds
        self.dbf_interval = 90  # 90 seconds in seconds
        self.qbf_interval = 540  # 9 minutes in seconds
        self.last_qbf_time = time.time()
        self.encoded_encID_set = set()

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

    def setup_encid_verification_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 48000))
        return sock

    def broadcast_shares(self):
        """Broadcasts shares over UDP with random drops."""
        while True:
            self.generate_new_ephid_and_shares()
            for share in self.current_shares:
                share_value_hex = binascii.hexlify(share[1]).decode()
                safe_print("\n------------------> Segment 3 <------------------")
                safe_print("Task 3: Preparing to broadcast Share", share[0])
                if random.random() < 0.1:
                    safe_print(f"Task 3a: Dropping share {share[0]} with value {share_value_hex}")
                    continue
                share_data = (
                    f"{share[0]}, {binascii.hexlify(share[1]).decode()}, {self.current_hash}"
                )
                self.server_socket.sendto(share_data.encode(), ("<broadcast>", 37025))
                safe_print("Task 3: Broadcasting share", share[0])
                time.sleep(3)
            time.sleep(15)  # Wait for 15 seconds before generating a new EphID

    def generate_new_ephid_and_shares(self):
        self.current_ephid, _ = generate_ephemeral_id()
        self.current_shares = generate_shares(self.current_ephid)
        self.current_hash = generate_hash(self.current_ephid)

    def listen_for_shares(self):
        """Listens for shares and processes them."""
        while True:
            data, _ = self.client_socket.recvfrom(1024)
            share_num, share, recv_hash_ephID = self.parse_share(data.decode())
            self.process_received_share(share_num, share, recv_hash_ephID)
            self.attempt_reconstruction(recv_hash_ephID)

    def parse_share(self, data):
        parts = data.split(",")
        share_num = int(parts[0].strip())
        share = binascii.unhexlify(parts[1].strip())
        recv_hash_ephID = parts[2].strip()
        return share_num, share, recv_hash_ephID

    def process_received_share(self, share_num, share, recv_hash_ephID):
        if recv_hash_ephID not in self.received_shares:
            self.received_shares[recv_hash_ephID] = []
        self.received_shares[recv_hash_ephID].append((share_num, share))
        safe_print(f"Task 3b: Received share {share_num} for hash {recv_hash_ephID}")
        safe_print(
            f"Task 3c: Total shares received for hash {recv_hash_ephID}: {len(self.received_shares[recv_hash_ephID])}, share value {binascii.hexlify(share).decode()}"
        )

    ############################## Task 4 ##############################
    # Segment 4-A: Show the nodes attempting re-construction of EphID when these have received at least 3 shares.
    # Segment 4-B: Show the nodes verifying the re-constructed EphID by taking the hash of re-constructed EphID and comparing with the hash value received in the advertisement.
    def attempt_reconstruction(self, recv_hash_ephID):
        if len(self.received_shares[recv_hash_ephID]) >= 3:
            safe_print(f"\n------------------> Segment 4 <------------------")
            safe_print(f"Task 4-A: Attempting to reconstruct EphID for hash {recv_hash_ephID}")
            safe_print(f"Number of shares available: {len(self.received_shares[recv_hash_ephID])}")

            shares = self.received_shares[recv_hash_ephID][:3]
            reconstructed_ephID = Shamir.combine(shares)

            safe_print(f"Task 4-B: Verifying reconstructed EphID")
            safe_print(f"Original EphID hash:    {recv_hash_ephID}")
            safe_print(f"Reconstructed EphID: {binascii.hexlify(reconstructed_ephID).decode()}")

            reconstructed_hash = generate_hash(reconstructed_ephID)
            safe_print(f"Reconstructed hash: {reconstructed_hash}")

            if reconstructed_hash == recv_hash_ephID:
                safe_print(f"Task 4-B: Verification successful: Reconstructed EphID matches the original!")
                safe_print(f"Successfully verified EphID: {binascii.hexlify(reconstructed_ephID).decode()}")
                self.construct_encID(reconstructed_ephID)  # Task 5
            else:
                safe_print("Task 4-B: Verification failed: Reconstructed EphID does not match the original.")
                safe_print(f"Expected hash:   {recv_hash_ephID}")
                safe_print(f"Calculated hash: {reconstructed_hash}")

    ############################## Task 5 ##############################
    # Segment 5-A: Show the nodes computing the shared secret EncID by using DiffieHellman key exchange mechanism.
    # Segment 5-B: Show that a pair of nodes have arrived at the same EncID value
    def construct_encID(self, ephID):
        """Compute the shared secret EncID using Diffie-Hellman key exchange"""
        self.ecdh.load_received_public_key_bytes(bytes([2]) + ephID)
        encID = self.ecdh.generate_sharedsecret_bytes()
        self.computed_encID = encID
        safe_print("\n------------------> Segment 5 <------------------")
        safe_print(
            f"Task 5-A: Generated shared secret EncID: {binascii.hexlify(encID).decode()}"
        )
        self.verify_encID(encID)

    def verify_encID(self, received_encID):
        """Verify the received EncID against the computed EncID"""
        if self.computed_encID is None:
            # EncID has already been processed and deleted
            return

        if self.computed_encID == received_encID:
            safe_print(
                f"Task 5-B: Successfully verified received EncID: {binascii.hexlify(received_encID).decode()}"
            )
            self.broadcast_encID(self.computed_encID)
        else:
            safe_print(
                f"Task 5-B: Verification failed for received EncID: {binascii.hexlify(received_encID).decode()}"
            )
    
    ############################## Task 6 ##############################
    # Segment 6:A node, after successfully constructing the EncID, will encode EncID into a Bloom filter called Daily Bloom Filter (DBF), and delete the EncID.
    def broadcast_encID(self, encID):
        """Broadcast the EncID to other nodes"""
        encID_data = binascii.hexlify(encID).decode()
        if encID in self.encoded_encID_set:
            safe_print(f"Skipping broadcast for already encoded EncID: {encID_data}")
            return

        self.encid_verification_socket.sendto(
            encID_data.encode(), ("<broadcast>", 48000)
        )
        safe_print(f"Broadcasting EncID: {encID_data}")
        self.encode_and_delete_encID(encID)
        self.encoded_encID_set.add(encID)

    def encode_and_delete_encID(self, encID):
        """Encode the EncID into the DBF and delete the EncID"""
        if encID is None or self.computed_encID is None:
            safe_print("Error: Attempted to encode None EncID or EncID already deleted")
            return

        safe_print("\n------------------> Segment 6 <------------------")
        safe_print(f"Current DBF state before encoding:")
        self.show_dbf_state()
        
        self.dbf.add(encID)
        safe_print(f"Encoded EncID into DBF: {binascii.hexlify(encID).decode()}")
        
        safe_print(f"DBF state after encoding:")
        self.show_dbf_state()
        
        safe_print(f"Deleting EncID from memory.")
        self.computed_encID = None  # Delete the EncID from memory
        
        safe_print(f"Verifying EncID deletion:")
        if self.computed_encID is None:
            safe_print("EncID successfully deleted from memory.")
        else:
            safe_print("Error: EncID not deleted from memory.")
        
        # To prevent re-broadcasting the same EncID
        self.encoded_encID_set.add(encID)


    def show_dbf_state(self):
        """Display the current state of the Bloom Filter"""
        total_bits = len(self.dbf.bit_array)
        set_bits = self.dbf.bit_array.count(1)
        percentage_set = (set_bits / total_bits) * 100
        
        safe_print(f"DBF size: {total_bits} bits")
        safe_print(f"Set bits: {set_bits}") 
        safe_print(f"Percentage of bits set: {percentage_set:.2f}%")
        

    def listen_for_encID(self):
        """Listen for EncID broadcasts and verify"""
        while True:
            data, _ = self.encid_verification_socket.recvfrom(1024)
            received_encID = binascii.unhexlify(data.decode())
            self.verify_encID(received_encID)     

    ############################## Task 7 ##############################
    # Segment 7-A:Show that the nodes are encoding multiple EncIDs into the same DBF and show the state of the DBF after each addition.
    # Segment 7-B:Show that a new DBF gets created for the nodes after every 90 seconds. A node can only store maximum of 6 DBFs.
    def manage_dbf_sampling(self):
        """Periodically sample and reset the DBF, and merge older DBFs when necessary."""
        while True:
            current_time = time.time()

            # Task 7-A: Check if a new DBF needs to be created
            if current_time - self.dbf_start_time >= self.dbf_interval:
                self.dbf_list.append(self.dbf)
                self.dbf = BloomFilter() 
                self.dbf_start_time = current_time
                safe_print("\n------------------> Segment 7-A <------------------")
                safe_print("Task 7-A: New DBF created and added to DBF list.")
                safe_print(f"Current number of DBFs: {len(self.dbf_list)}")

            # Task 7-B: Remove DBFs older than dbf_max_age
            original_dbf_count = len(self.dbf_list)
            self.dbf_list = [dbf for dbf in self.dbf_list if current_time - dbf.dbf_start_time <= self.dbf_max_age]
            removed_dbf_count = original_dbf_count - len(self.dbf_list)

            if removed_dbf_count > 0:
                safe_print("\n------------------> Segment 7-B <------------------")
                safe_print(f"Task 7-B: Removed {removed_dbf_count} DBFs older than {self.dbf_max_age} seconds.")
                safe_print(f"Remaining DBFs: {len(self.dbf_list)}")

            # Ensure no more than 6 DBFs are stored at any time
            while len(self.dbf_list) > 6:
                removed_dbf = self.dbf_list.pop(0)
                safe_print("\n------------------> Segment 7-B <------------------")
                safe_print("Task 7-B: Removed the oldest DBF to maintain the limit of 6 DBFs.")
                safe_print(f"Remaining DBFs: {len(self.dbf_list)}")

            ############################## Task 8 ##############################
            # Segment 8:Show that after every 9 minutes, the nodes combine all the available DBFs into a single QBF.
            if current_time - self.last_qbf_time >= self.qbf_interval:
                qbf = BloomFilter()
                for dbf in self.dbf_list:
                    qbf.bit_array |= dbf.bit_array

                safe_print("\n------------------> Segment 8 <------------------")
                safe_print(f"Task 8: Combined DBFs into QBF with {qbf.bit_array.count()} set bits.")

                self.last_qbf_time = current_time  # Reset start time after upload

            time.sleep(1) 


    def start(self):
        threading.Thread(
            target=self.broadcast_shares, name="BroadcastThread", daemon=True
        ).start()
        threading.Thread(
            target=self.listen_for_shares, name="ListenThread", daemon=True
        ).start()
        threading.Thread(
            target=self.listen_for_encID, name="EncIDListenThread", daemon=True
        ).start()
        threading.Thread(
            target=self.manage_dbf_sampling, name="DBFSamplingThread", daemon=True
        ).start()

def main():
    stop_printing = threading.Event()
    print_thread = threading.Thread(target=print_manager, args=(stop_printing,))
    print_thread.start()

    manager = ShareManager()
    manager.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_printing.set()

    output_queue.put("STOP")
    print_thread.join()

if __name__ == "__main__":
    main()