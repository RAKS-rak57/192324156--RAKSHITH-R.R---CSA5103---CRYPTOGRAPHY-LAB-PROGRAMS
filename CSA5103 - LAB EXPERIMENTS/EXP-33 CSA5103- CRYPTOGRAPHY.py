from Crypto.Cipher import DES

# DES key (64 bits, including 8 parity bits)
key = bytes.fromhex("133457799BBCDFF1")

# 64-bit plaintext
plaintext = bytes.fromhex("0123456789ABCDEF")

# Create DES encryption object
encryptor = DES.new(key, DES.MODE_ECB)

# Encryption
ciphertext = encryptor.encrypt(plaintext)

print("Plaintext  :", plaintext.hex().upper())
print("DES Key    :", key.hex().upper())
print("Ciphertext :", ciphertext.hex().upper())

# Decryption
decryptor = DES.new(key, DES.MODE_ECB)

decrypted = decryptor.decrypt(ciphertext)

print("Decrypted  :", decrypted.hex().upper())

if decrypted == plaintext:
    print("DES encryption and decryption successful!")
else:
    print("Decryption failed!")
