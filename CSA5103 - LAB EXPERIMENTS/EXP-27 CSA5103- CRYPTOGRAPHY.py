from math import gcd

# RSA key generation
p = 1000003
q = 1000033

n = p * q
phi = (p - 1) * (q - 1)

e = 65537

if gcd(e, phi) != 1:
    raise ValueError("Invalid public exponent")

d = pow(e, -1, phi)

# Message
message = "HELLO"

# Convert characters into numbers (A=0, B=1, ..., Z=25)
numbers = [ord(ch) - ord('A') for ch in message]

# Encrypt each character separately
ciphertext = [pow(num, e, n) for num in numbers]

print("Original message:", message)
print("Encrypted characters:", ciphertext)

# Attacker's approach: use only public key (e, n)
lookup = {}

for num in range(26):
    encrypted = pow(num, e, n)
    lookup[encrypted] = chr(num + ord('A'))

# Recover the message using the lookup table
recovered = ""

for value in ciphertext:
    recovered += lookup[value]

print("Recovered message:", recovered)
