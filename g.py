#! /usr/bin/env python3

# EphID and Shamir Secret Sharing Mechanism
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import hashlib
import base64

# Threading
import threading

from json import dumps

# UDP Programming
import socket
import time

import datetime
import binascii

from ecdsa import ECDH, SECP128r1, VerifyingKey

# bloom filter library
import bitarray
import bitarray.util
import mmh3
import math

from Crypto.Random.random import getrandbits
from random import randint

import requests

server = None
client = None
server_url = 'http://127.0.0.1:55000'


############################## Task 1/2 ##############################
# Every 60 seconds, generate new EphID and associated shares

ephID = None
ecdh = None
def genEphID():
    '''
    Generates a 16 Byte ephemeral ID using ECDH
    Stores in global ephID variable
    '''
    global ecdh
    global ephID
    global hash_ephID
    
    ecdh = ECDH(curve=SECP128r1)

    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()
    ephID = public_key.to_string('compressed')[1:]

hash_ephID = None
def genHashEphID():
    '''
    Generates a hash of the ephemeral ID
    Stores hash in global hash_ephID variable
    '''
    global hash_ephID

    hash_ephID = hashlib.sha256(ephID).hexdigest()

# Variable to hold shares, hash of EphID, temporarily store Ephemeral ID
send_shares = None
def genShares():
    '''
    Generates n shares of the EphID by using k-out-of-n Shamir Secret Sharing mechanism
    k = 3, n = 6
    Stores shares in global send_shares variable
    '''
    global send_shares

    send_shares = Shamir.split(3, 6, ephID)

def genEphIDHashShares():
    '''
    Generates a 16-Byte Ephemeral ID, hash of the Ephemeral ID, and Shamir Secret Shares
    Repeats every minute
    Stores in global ephID, hash_ephID, send_shares variables
    '''
    global ephID
    global hash_ephID
    global send_shares

    while (True):
        genEphID()
        genHashEphID()
        genShares()

        print("\n------------------> Segment 1 <------------------")
        print(f"generate EphID: {ephID}")
        print(f"hash value of EphID: {hash_ephID}\n")

        print("------------------> Segment 2 <------------------")
        print("[")
        for share in send_shares:
            print(f"\t{share[1]}")
        print("]")

        time.sleep(60)

# Start thread to generate ephID, hash, and shares every minute
ephID_thread = threading.Thread(target=genEphIDHashShares, args=(), name="Generates Epheremal ID from hash shares.")


############################## TASK 3 ##############################
# Send and receive shares

# Task 3A: Broadcast n shares at rate of 1 unique share per 10 seconds. 
# References UDP socket programming https://github.com/ninedraft/python-udp
def user_send():
    '''
    User broadcasts one share of the EphID every 10 seconds to another user
    '''

    # Determine shares of EphID
    global ephID
    global hash_ephID
    global send_shares

    i = 0
    while True:
        # Convert share to bytes
        share = (send_shares[i][0], binascii.hexlify(send_shares[i][1]), hash_ephID)
        share_bytes = str.encode(str(share))

        print(f"\n[ Segment 3-A, sending share: {share[1]} ]")

        # NOTE: Use for Laptop broadcasts
        server.sendto(share_bytes, ('<broadcast>', 37025))
        # NOTE: Use for Raspberry Pi broadcasts
        # server.sendto(share_bytes, ('192.168.4.255', 37025))

        # Increment to next share
        if (i == 5):
            i = 0
        else:
            i += 1

        # Send every 10 seconds
        time.sleep(10)

# Task 3-B: Receive shares broadcasted by other device
recv_shares = None
def add_share(recv_hash, recv_share):
    '''
    Adds a share (share_num, share_bytes) to the global recv_shares variable
    '''
    global recv_shares

    is_hash_in_shares = False

    for share in recv_shares:
        # Check if hash is already in shares
        if share['hash'] == recv_hash:
            is_hash_in_shares = True
            # If hash already in shares, append non-duplicate shares
            if recv_share not in share['shares']:
                share['shares'].append(recv_share)
    
    if not is_hash_in_shares:
        # If hash not in shares, create new object with this share
        recv_shares.append(
            {
                "hash": recv_hash,
                "shares": [recv_share],
                "ephID": None
            }
        )

def add_eph_id_to_shares(recv_hash, recv_ephID):
    '''
    Adds ephID to global shares variable
    After ephID is reconstructed
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            share['ephID'] = recv_ephID

def num_shares_received(recv_hash):
    '''
    Determines number of unique shares received for a given hash of an EphID
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            return len(share['shares'])

    return 0

def has_k_shares(k, recv_hash):
    '''
    Determines if the receiver has enough of rec_hash shares 
    to reconstruct the sender's EphID
    and if the EphID was not already reconstructed
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            if share['ephID'] is None:
                return len(share['shares']) >= k

    return False

def user_receive():
    '''
    User receives broadcast from another user
    '''
    global recv_shares
    recv_shares = []
    recv_hash_ephID = None

    while True:
        # Receive data
        data, addr = client.recvfrom(1024)

        # Convert data to (share number, share)
        data_str = data.decode()
        share_num = int(data_str.split(',')[0].replace("(", ""))
        share_hex = data_str.split(', b')[1].split(',')[0].replace(")", "").replace(" ", "").replace("'", "")
        recv_hash_ephID = data_str.split(', b')[1].split(',')[1].replace(")", "").replace(" ", "").replace("'", "")
        share_bytes = binascii.unhexlify(share_hex)
        share = (share_num, share_bytes)

        # Do not receive own share
        if (recv_hash_ephID != hash_ephID):
            
            print(f"[ Segment 3-B, received share for hash {recv_hash_ephID}: {share[1]} ]")
            
            # Add to shares
            add_share(recv_hash_ephID, share)
            print(f"[ Segment 3-C, total shares received for hash {recv_hash_ephID}: {num_shares_received(recv_hash_ephID)} ]")

            # Task 4: If have 3 shares for that hash and ephID not reconstructed for that hash then
            # reconstruct ephID and check hash
            if has_k_shares(3, recv_hash_ephID):
                reconstruct_verify_ephID(recv_hash_ephID)

def send_recv_threads():
    global server
    global client
    
    ########## SENDER ##########
    # UDP socket programming references https://github.com/ninedraft/python-udp

    # Create UDP socket for sender
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Enable port reusage so we can run multiple clients/servers on single (host/port)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Enable broadcasting mode
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Set a timeout so the socket does not block indefinitely when trying to receive data.
    server.settimeout(0.2)
    # Bind socket to localhost port 44444
    server.bind(("", 44444))

    print("\n------------------> Segment 3 <------------------")
    # Create thread for user to broadcast chunks of the EphID
    message = ephID
    send_broadcast_thread = threading.Thread(target=user_send, name="Sending Thread")
    send_broadcast_thread.start()

    ########## RECEIVER ##########

    # Create UDP socket for receiver
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Enable port reusage so we will be able to run multiple clients and servers on single (host, port).
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Enable broadcasting mode
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind socket to localhost port 37024
    client.bind(("", 37025))

    # Create thread for user to receive broadcasts
    recv_broadcast_thread = threading.Thread(target=user_receive, name="Receiving Thread")
    recv_broadcast_thread.start()


############################## TASK 4 ##############################
# Reconstruct ephID and verify

# Task 4: 4-A Show the devices attempting re-construction of EphID when these have received at least 3 shares.
# Task 4: 4-B Show the devices verifying the re-constructed EphID by taking the hash of re-constructed EphID and comparing with the hash value received in the advertisement.

def reconstruct_eph_id(rec_hash):
    '''
    Reconstructs a sender's ephID from the received shares
    '''
    global recv_shares
    ephID = None

    for share in recv_shares:
        if share['hash'] == rec_hash:
            ephID = Shamir.combine(share['shares'])
    
    return ephID

def verify_eph_id(ephID, hash_ephID):
    '''
    Verifies ephID by reconstructing the received hash of the ephID
    Returns True if match, False otherwise
    '''
    return hashlib.sha256(ephID).hexdigest() == hash_ephID

def reconstruct_verify_ephID(hash_ephID=None):
    '''
    Reconstructs an ephID from atleast 3 shares
    Verifies hash of that ephID with the hash sent
    '''
    global recv_shares

    # Task 4: 4-A Show the devices attempting re-construction of EphID 
    # when these have received at least 3 shares.
    if has_k_shares(3, hash_ephID):
        ephID = reconstruct_eph_id(hash_ephID)

        print("\n------------------> Segment 4 <------------------")
        print(f"[ Segment 4-A, re-construct EphID: {ephID} ]")
        print(f"[ Segment 4-B, hash value of re-constructed EphID: {hashlib.sha256(ephID).hexdigest()} is equal to hash value of original EphID: {hash_ephID}")

        # Verify hashes equal before storing Ephemeral ID and computing Encounter ID
        if (hashlib.sha256(ephID).hexdigest() == hash_ephID):
            # Store ephID in shares variable
            add_eph_id_to_shares(hash_ephID, ephID)

            # Once we have reconstructed Ephemeral ID, compute the Encounter ID
            construct_encID(ephID)


############################## TASK 5 ##############################
# Compute EncID

# Task 5: 5-A Show the devices computing the shared secret EncID by using Diffie-Hellman key exchange mechanism.
# Task 5: 5-B Show that the devices have arrived at the same EncID value.
encID = None
def construct_encID(ephID):
    '''
    Computes encID given an ephID
    '''
    global ecdh
    global encID

    # Need to add 2 or 3 to the beginning of EphID
    ephID = bytes([2]) + ephID

    # Compute EncID
    ecdh.load_received_public_key_bytes(ephID)
    encID = ecdh.generate_sharedsecret_bytes()

    print("\n------------------> Segment 5 <------------------")
    print(f"[ generate shared secret EncID: {encID} ]")

if __name__ == "__main__":
    # Start ephID thread
    ephID_thread.start()

    time.sleep(1)
    
    # Start sending shares and receiving them
    send_recv_threads()
