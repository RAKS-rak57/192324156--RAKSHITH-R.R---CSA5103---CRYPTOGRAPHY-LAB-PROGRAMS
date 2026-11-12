
from collections import Counter

# Approximate English letter frequencies
english = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228,
    2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
    2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
    6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
]

def decrypt(ciphertext, shift):
    result = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base - shift) % 26 + base)
        else:
            result += ch
    return result

def score(text):
    letters = [ch.upper() for ch in text if ch.isalpha()]
    n = len(letters)

    if n == 0:
        return float("inf")

    counts = Counter(letters)
    chi = 0

    for i in range(26):
        expected = n * english[i] / 100
        observed = counts.get(chr(65 + i), 0)

        if expected > 0:
            chi += (observed - expected) ** 2 / expected

    return chi

ciphertext = input("Enter ciphertext: ")
top_n = int(input("How many candidates? "))

candidates = []

for shift in range(26):
    plaintext = decrypt(ciphertext, shift)
    candidates.append((score(plaintext), shift, plaintext))

candidates.sort()

print("\nTop possible plaintexts:")
for rank, (value, shift, plaintext) in enumerate(
        candidates[:max(0, min(top_n, 26))], 1):
    print(f"{rank}. Shift {shift}: {plaintext}")
