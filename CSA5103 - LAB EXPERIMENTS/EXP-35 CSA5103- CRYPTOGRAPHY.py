import secrets

# Read plaintext
plaintext = input("Enter plaintext: ").upper()

# Generate random key stream
key = [
    secrets.randbelow(26)
    for ch in plaintext if ch.isalpha()
]

ciphertext = ""
decrypted = ""

j = 0

for ch in plaintext:
    if ch.isalpha():
        # Convert character into number (A=0 to Z=25)
        P = ord(ch) - ord('A')

        # Encryption
        C = (P + key[j]) % 26
        ciphertext += chr(C + ord('A'))

        # Decryption
        D = (C - key[j]) % 26
        decrypted += chr(D + ord('A'))

        j += 1
    else:
        ciphertext += ch
        decrypted += ch

print("\nRandom Key Stream:", key)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted)
