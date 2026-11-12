
def encrypt(plaintext, key):
    text = ''.join(ch for ch in plaintext.upper() if ch.isalpha())
    return ''.join(
        chr((ord(ch) - 65 + k) % 26 + 65)
        for ch, k in zip(text, key)
    )

def find_key(ciphertext, target):
    return [
        (ord(c) - 65 - (ord(p) - 65)) % 26
        for c, p in zip(ciphertext, target)
    ]

plaintext = "send more money"
key = [9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9]

ciphertext = encrypt(plaintext, key)
target = "cash not needed"
recovered_key = find_key(ciphertext, target.replace(" ", "").upper())

print("Part (a)")
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("\nPart (b)")
print("Target plaintext:", target)
print("Required key stream:", recovered_key)
