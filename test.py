# Example test script
from secretsharing import SecretSharer  # Adjust based on the actual library

secret = "1234567890abcdef1234567890abcdef"
shares = SecretSharer.split_secret(secret, 3, 5)
print(shares)
reconstructed = SecretSharer.recover_secret(shares[:3])
print(reconstructed)
