import os
import time
import socket
import random
import hashlib
import threading
from secretsharing import SecretSharer

def generate_ephemeral_id(): # task 1
    """Generates a 32-byte random EphID."""
    return os.urandom(32)  # Generates 32 bytes of random data

def split_ephemeral_id(eph_id, n=5, k=3): # task 2  
    """Splits the EphID into n shares such that any k shares can reconstruct the EphID."""
    # Convert EphID bytes to hex string as required by the SecretSharer library
    hex_eph_id = eph_id.hex()
    # Splitting the hex string into shares
    shares = SecretSharer.split_secret(hex_eph_id, k, n)
    return shares

def broadcast_shares(): # task 3 + 3a
    """Broadcasts shares over UDP with error handling in a loop."""
    while True:
        eph_id = generate_ephemeral_id()
        hex_eph_id = eph_id.hex()
        print(f"EphID Generated: {hex_eph_id}")
        shares = split_ephemeral_id(eph_id)
        eph_id_hash = hashlib.sha256(eph_id).hexdigest()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_ip = '255.255.255.255'
            port = 50000

            for share in shares:
                share_data = f"{eph_id_hash}:{share}"
                if random.random() < 0.5:
                    print(f"Share Dropped: {share_data}")
                    continue
                
                sock.sendto(share.encode(), (broadcast_ip, port))
                print(f"Broadcasted Share: {share_data}")
                time.sleep(3)  # Sleep between each share to mimic the broadcast delay
        except Exception as e:
            print(f"An error occurred during broadcasting: {e}")
        finally:
            sock.close()
        
        time.sleep(12)  # Adjusted to sync with the overall cycle of EphID generation

def listen_for_shares(): # task 
    """Listens for shares and attempts to reconstruct the EphID when sufficient shares are collected."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 50000))
    shares_collected = {}
    eph_id_hashes = {}

    while True:
        data, _ = sock.recvfrom(1024)
        share_data = data.decode()
        hash_value, share = share_data.split(':', 1)
        print(f"Received Share: {share} for Hash: {hash_value}")

        if hash_value not in shares_collected:
            shares_collected[hash_value] = []
            eph_id_hashes[hash_value] = hash_value

        shares_collected[hash_value].append(share)

        if len(shares_collected[hash_value]) >= 3:
            try:
                reconstructed_hex_eph_id = SecretSharer.recover_secret(shares_collected[hash_value][:3])
                reconstructed_eph_id = bytes.fromhex(reconstructed_hex_eph_id)
                reconstructed_hash = hashlib.sha256(reconstructed_eph_id).hexdigest()

                print(f"Reconstructed EphID: {reconstructed_hex_eph_id}")
                print(f"Verification Hash: {reconstructed_hash}")
                if reconstructed_hash == eph_id_hashes[hash_value]:
                    print("Verification Successful")
                else:
                    print("Verification Failed")
            except Exception as e:
                print(f"Error reconstructing EphID: {e}")

def main():
    broadcaster = threading.Thread(target=broadcast_shares)
    listener = threading.Thread(target=listen_for_shares)
    
    broadcaster.start()
    listener.start()

    broadcaster.join()
    listener.join()

if __name__ == "__main__":
    main()
