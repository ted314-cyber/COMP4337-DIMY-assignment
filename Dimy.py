import os
import time
from secretsharing import SecretSharer

def generate_ephemeral_id():
    """Generates a 32-byte random EphID."""
    return os.urandom(32)  # Generates 32 bytes of random data

def split_ephemeral_id(eph_id, n=5, k=3):
    """Splits the EphID into n shares such that any k shares can reconstruct the EphID."""
    # Convert EphID bytes to hex string as required by the SecretSharer library
    hex_eph_id = eph_id.hex()
    # Splitting the hex string into shares
    shares = SecretSharer.split_secret(hex_eph_id, k, n)
    return shares

def main():
    while True:
        eph_id = generate_ephemeral_id()
        print(f"EphID Generated: {eph_id.hex()}")  # Print the hex representation of EphID
        
        # Splitting the EphID into shares
        shares = split_ephemeral_id(eph_id)
        for share in shares:
            print(f"Share Generated: {share}")
        
        time.sleep(15)  # Wait for 15 seconds before generating the next EphID

if __name__ == "__main__":
    main()
