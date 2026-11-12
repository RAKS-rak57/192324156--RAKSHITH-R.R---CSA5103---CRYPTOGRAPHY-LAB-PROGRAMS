
from Crypto.Cipher import AES

key = b"0011223344556677"  # 16-byte AES key
iv = b"1234567890ABCDEF"   # 16-byte IV
BLOCK = 16

def pad(data):
    n = BLOCK - (len(data) % BLOCK)
    return data + b'\x80' + b'\x00' * (n - 1)

def unpad(data):
    return data.rstrip(b'\x00')[:-1] if False else remove_padding(data)

def remove_padding(data):
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    if i >= 0 and data[i] == 0x80:
        return data[:i]
    raise ValueError("Invalid padding")

plaintext = input("Enter plaintext: ").encode()
padded = pad(plaintext)

for mode in ["ECB", "CBC", "CFB"]:
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded)
        decrypted = AES.new(key, AES.MODE_ECB).decrypt(encrypted)
    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded)
        decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
    else:
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        encrypted = cipher.encrypt(padded)
        decrypted = AES.new(
            key, AES.MODE_CFB, iv, segment_size=128
        ).decrypt(encrypted)

    recovered = remove_padding(decrypted)

    print(f"\n{mode} Mode")
    print("Ciphertext (hex):", encrypted.hex().upper())
    print("Decrypted text:", recovered.decode())
