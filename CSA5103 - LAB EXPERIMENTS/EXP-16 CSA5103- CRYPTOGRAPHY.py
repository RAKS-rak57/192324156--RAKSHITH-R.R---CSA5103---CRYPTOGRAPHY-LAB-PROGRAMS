
from collections import Counter
import string

ENGLISH_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def decrypt_with_mapping(ciphertext, mapping):
    result = ""
    for ch in ciphertext.upper():
        if ch in mapping:
            result += mapping[ch]
        else:
            result += ch
    return result

def english_score(text):
    common = [
        "THE", "AND", "ING", "ION", "ENT", "HER",
        "FOR", "THA", "NTH", "INT", "ERE", "TIO",
        "TER", "EST", "ERS", "ATI", "HAT", "ATE",
        "ALL", "ETH", "HES", "VER"
    ]
    text = text.upper()
    return sum(text.count(pattern) * len(pattern)
               for pattern in common)

ciphertext = input("Enter ciphertext: ").upper()
top_n = int(input("Number of candidates: "))
top_n = max(1, min(top_n, 26))

letters = [ch for ch in ciphertext if ch in string.ascii_uppercase]
frequency = Counter(letters)
cipher_order = [ch for ch, _ in frequency.most_common()]

# Add unused letters so every candidate has a complete mapping
cipher_order += [ch for ch in string.ascii_uppercase
                 if ch not in cipher_order]

candidates = []

# Generate alternative frequency mappings by rotating
# the expected English letter-frequency order.
for shift in range(26):
    mapping = {
        cipher_order[i]: ENGLISH_FREQ[(i + shift) % 26]
        for i in range(26)
    }
    plaintext = decrypt_with_mapping(ciphertext, mapping)
    candidates.append((english_score(plaintext), plaintext, shift))

candidates.sort(key=lambda item: item[0], reverse=True)

print("\nPossible plaintexts (heuristic ranking):")
for rank, (score, plaintext, shift) in enumerate(candidates[:top_n], 1):
    print(f"{rank}. {plaintext}")
