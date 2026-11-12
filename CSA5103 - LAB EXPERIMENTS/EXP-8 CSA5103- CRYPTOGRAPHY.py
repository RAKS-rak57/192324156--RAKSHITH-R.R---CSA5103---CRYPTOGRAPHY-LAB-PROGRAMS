
import string

# Read input
keyword = input("Enter keyword: ").upper()
plaintext = input("Enter plaintext: ")

alphabet = string.ascii_uppercase

# Remove duplicate letters and keep the first occurrence
unique_keyword = ""
for ch in keyword:
    if ch.isalpha() and ch not in unique_keyword:
        unique_keyword += ch

# Append unused alphabet letters
cipher_alphabet = unique_keyword
for ch in alphabet:
    if ch not in cipher_alphabet:
        cipher_alphabet += ch

# Create substitution mapping
mapping = dict(zip(alphabet, cipher_alphabet))

# Encrypt plaintext
ciphertext = ""
for ch in plaintext:
    if ch.isalpha():
        encrypted = mapping[ch.upper()]
        ciphertext += encrypted if ch.isupper() else encrypted.lower()
    else:
        ciphertext += ch

# Display results
print("\nPlain alphabet:")
print(alphabet)

print("\nCipher alphabet:")
print(cipher_alphabet)

print("\nEncrypted text:")
print(ciphertext)
