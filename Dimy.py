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

def split_ephemeral_id(eph_id, n=5, k=3):
    """Splits the EphID into n shares such that any k shares can reconstruct the EphID."""
    # Convert EphID bytes to hex string as required by the SecretSharer library
    hex_eph_id = eph_id.hex()
    # Splitting the hex string into shares
    shares = SecretSharer.split_secret(hex_eph_id, k, n)
    return shares

def broadcast_shares():
    """Broadcasts shares over UDP with error handling in a loop."""
    while True:
        eph_id = generate_ephemeral_id()
        print(f"EphID Generated: {eph_id.hex()}")
        shares = split_ephemeral_id(eph_id)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_ip = '255.255.255.255'
            port = 50000

            for share in shares:
                if random.random() < 0.5:
                    print(f"Share Dropped: {share}")
                    continue
                
                sock.sendto(share.encode(), (broadcast_ip, port))
                print(f"Broadcasted Share: {share}")
                time.sleep(3)  # Sleep between each share to mimic the broadcast delay
        except Exception as e:
            print(f"An error occurred during broadcasting: {e}")
        finally:
            sock.close()
        
        time.sleep(12)  # Adjusted to sync with the overall cycle of EphID generation

def listen_for_shares():
    """Listens for shares and attempts to reconstruct the EphID when sufficient shares are collected."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 50000))
    shares_collected = {}

    while True:
        data, _ = sock.recvfrom(1024)
        share = data.decode()
        print(f"Received Share: {share}")

        # Simple logic to collect and check shares
        if share not in shares_collected:
            shares_collected[share] = []
        shares_collected[share].append(share)

        if len(shares_collected[share]) >= 3:
            try:
                reconstructed_hex_eph_id = SecretSharer.recover_secret(shares_collected[share][:3])
                reconstructed_eph_id = bytes.fromhex(reconstructed_hex_eph_id)
                print(f"Reconstructed EphID: {reconstructed_hex_eph_id}")

                hash_digest = hashlib.sha256(reconstructed_eph_id).hexdigest()
                print(f"Verification Hash: {hash_digest}")
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
