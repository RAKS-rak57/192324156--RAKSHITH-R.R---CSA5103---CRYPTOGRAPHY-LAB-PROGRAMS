
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad

plaintext = input("Enter plaintext: ")

# 24-byte (192-bit) 3DES key
key = bytes.fromhex(
    "0123456789ABCDEFFEDCBA98765432100011223344556677"
)

# 8-byte initialization vector
iv = bytes.fromhex("1234567890ABCDEF")

cipher = DES3.new(key, DES3.MODE_CBC, iv)

ciphertext = cipher.encrypt(
    pad(plaintext.encode("utf-8"), DES3.block_size)
)

print("\nCBC Encryption using 3DES")
print("Ciphertext (hex):", ciphertext.hex().upper())
