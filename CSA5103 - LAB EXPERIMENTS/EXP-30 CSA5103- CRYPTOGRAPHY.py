from Crypto.Cipher import AES

# Secret key (16 bytes)
key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")

cipher = AES.new(key, AES.MODE_ECB)

# One-block message X (16 bytes)
X = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172A")

# CBC-MAC for a one-block message
T = cipher.encrypt(X)

# Construct second block Y = X XOR T
Y = bytes(a ^ b for a, b in zip(X, T))

# Two-block message X || Y
message = X + Y

# CBC-MAC calculation
state = bytes(16)

for i in range(0, len(message), 16):
    block = message[i:i + 16]
    state = cipher.encrypt(
        bytes(a ^ b for a, b in zip(state, block))
    )

two_block_mac = state

print("One-block message X:", X.hex().upper())
print("MAC of X (T):", T.hex().upper())
print("Second block (X XOR T):", Y.hex().upper())
print("Two-block MAC:", two_block_mac.hex().upper())

print("\nForgery successful:", T == two_block_mac)
