
from Crypto.Cipher import AES

key = b"0123456789ABCDEF"
iv = b"FEDCBA9876543210"

blocks = [
    b"0123456789ABCDEF",
    b"FEDCBA9876543210",
    b"THIRD-BLOCK-1234"
]
plaintext = b"".join(blocks)

# ECB encryption
ecb_cipher = AES.new(key, AES.MODE_ECB)
ecb_ct = ecb_cipher.encrypt(plaintext)

# CBC encryption
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ct = cbc_cipher.encrypt(plaintext)

# Introduce one bit error in the first ciphertext block
ecb_bad = bytearray(ecb_ct)
cbc_bad = bytearray(cbc_ct)
ecb_bad[0] ^= 1
cbc_bad[0] ^= 1

ecb_plain = AES.new(key, AES.MODE_ECB).decrypt(bytes(ecb_bad))
cbc_plain = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(cbc_bad))

print("ECB: blocks unchanged?")
for i in range(3):
    print(f"P{i+1}:", "Unchanged" if ecb_plain[i*16:(i+1)*16] == blocks[i]
          else "Corrupted")

print("\nCBC: blocks unchanged?")
for i in range(3):
    print(f"P{i+1}:", "Unchanged" if cbc_plain[i*16:(i+1)*16] == blocks[i]
          else "Corrupted")
