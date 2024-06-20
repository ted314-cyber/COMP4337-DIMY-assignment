import os
import time
import socket
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

def broadcast_shares(shares):
    """Broadcasts each share over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_ip = '255.255.255.255'  # Local network broadcast IP
    port = 50000  # Arbitrary non-privileged port

    for share in shares:
        sock.sendto(share.encode(), (broadcast_ip, port))
        print(f"Broadcasted Share: {share}")
        time.sleep(3)  # Wait for 3 seconds before sending the next share

    sock.close()

def main():
    while True:
        eph_id = generate_ephemeral_id()
        print(f"EphID Generated: {eph_id.hex()}")  # Print the hex representation of EphID
        
        # Splitting the EphID into shares (task 2)
        shares = split_ephemeral_id(eph_id)
        # Broadcasting shares (task 3)
        broadcast_shares(shares)
        
        time.sleep(15)  # Wait for 15 seconds before generating the next EphID

if __name__ == "__main__":
    main()
