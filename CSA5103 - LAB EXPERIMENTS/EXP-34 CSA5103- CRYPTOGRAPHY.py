from Crypto.Cipher import AES

# AES key and IV (128 bits each)
key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

# Plaintext
plaintext = b"HELLO AES MODES"

# Padding: 1 bit followed by zero bits
def add_padding(data):
    padding_length = 16 - (len(data) % 16)
    return data + b'\x80' + b'\x00' * (padding_length - 1)

def remove_padding(data):
    index = data.rfind(b'\x80')

    if index == -1 or any(data[index + 1:]):
        raise ValueError("Invalid padding")

    return data[:index]

padded = add_padding(plaintext)

# ECB encryption and decryption
ecb = AES.new(key, AES.MODE_ECB)
ecb_cipher = ecb.encrypt(padded)
ecb_plain = remove_padding(ecb.decrypt(ecb_cipher))

# CBC encryption and decryption
cbc = AES.new(key, AES.MODE_CBC, iv)
cbc_cipher = cbc.encrypt(padded)
cbc_plain = remove_padding(
    AES.new(key, AES.MODE_CBC, iv).decrypt(cbc_cipher)
)

# CFB encryption and decryption (128-bit segment)
cfb = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
cfb_cipher = cfb.encrypt(padded)
cfb_plain = remove_padding(
    AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    .decrypt(cfb_cipher)
)

print("Original plaintext:", plaintext.decode())
print("Padded plaintext:", padded.hex().upper())

print("\nECB Ciphertext:", ecb_cipher.hex().upper())
print("ECB Decrypted:", ecb_plain.decode())

print("\nCBC Ciphertext:", cbc_cipher.hex().upper())
print("CBC Decrypted:", cbc_plain.decode())

print("\nCFB Ciphertext:", cfb_cipher.hex().upper())
print("CFB Decrypted:", cfb_plain.decode())
