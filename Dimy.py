import os
import time

def generate_ephemeral_id():
    """Generates a 32-byte random EphID."""
    return os.urandom(32)  # Generates 32 bytes of random data

def main():
    while True:
        eph_id = generate_ephemeral_id()
        print(f"EphID Generated: {eph_id.hex()}")  # Print the hex representation of EphID
        time.sleep(15)  # Wait for 15 seconds before generating the next EphID

if __name__ == "__main__":
    main()
