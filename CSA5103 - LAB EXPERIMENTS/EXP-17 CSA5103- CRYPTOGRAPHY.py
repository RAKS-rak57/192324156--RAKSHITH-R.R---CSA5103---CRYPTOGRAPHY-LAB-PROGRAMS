
from Crypto.Cipher import DES

key_hex = input("Enter 16-digit hexadecimal key: ").strip()
cipher_hex = input("Enter ciphertext in hexadecimal: ").strip()

try:
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(cipher_hex)

    if len(key) != 8:
        raise ValueError("DES key must contain 8 bytes (16 hex digits).")

    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must be a non-empty multiple of 8 bytes.")

    # DES decryption internally applies round keys in reverse order:
    # K16, K15, ..., K1.
    des = DES.new(key, DES.MODE_ECB)
    plaintext = des.decrypt(ciphertext)

    print("\nDecrypted plaintext (hex):", plaintext.hex().upper())

    try:
        print("Decrypted plaintext (text):", plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print("Plaintext is binary data; use the hexadecimal output.")

except ValueError as error:
    print("Error:", error)
