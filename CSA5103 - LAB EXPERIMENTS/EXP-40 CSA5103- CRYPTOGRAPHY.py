import string
import random
from collections import Counter

ENGLISH_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

COMMON_BIGRAMS = [
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT",
    "EN", "ND", "TI", "ES", "OR", "TE", "OF", "ED"
]

COMMON_TRIGRAMS = [
    "THE", "AND", "ING", "HER", "ERE", "ENT",
    "THA", "NTH", "WAS", "ETH", "FOR", "DTH"
]

COMMON_WORDS = [
    "THE", "AND", "THAT", "HAVE", "FOR", "NOT",
    "WITH", "YOU", "THIS", "FROM", "ARE", "WAS",
    "WERE", "HELLO", "WORLD", "IS", "TO", "OF"
]


def decrypt(ciphertext, key):
    result = ""

    for ch in ciphertext:
        if ch.upper() in key:
            plain = key[ch.upper()]
            result += plain if ch.isupper() else plain.lower()
        else:
            result += ch

    return result


def score_text(text):
    clean = "".join(ch for ch in text.upper() if ch in string.ascii_uppercase)

    score = 0

    for bg in COMMON_BIGRAMS:
        score += clean.count(bg) * 2

    for tg in COMMON_TRIGRAMS:
        score += clean.count(tg) * 5

    words = text.upper().split()

    for word in words:
        if word in COMMON_WORDS:
            score += 10

    return score


def frequency_attack(ciphertext, top_n):
    letters = [ch.upper() for ch in ciphertext if ch.isalpha()]
    if not letters:
        print("No alphabetic characters found.")
        return

    frequency = Counter(letters)

    cipher_order = [
        letter for letter, count in frequency.most_common()
    ]

    # Add letters not present in the ciphertext
    for letter in string.ascii_uppercase:
        if letter not in cipher_order:
            cipher_order.append(letter)

    # Initial frequency-based substitution
    base_key = {
        cipher_order[i]: ENGLISH_FREQ[i]
        for i in range(26)
    }

    random.seed(42)
    candidates = {}

    # Generate alternative substitution mappings
    for _ in range(10000):
        key = base_key.copy()

        # Change a few letter assignments
        for _ in range(random.randint(1, 5)):
            a, b = random.sample(list(key.keys()), 2)
            key[a], key[b] = key[b], key[a]

        plaintext = decrypt(ciphertext, key)
        candidates[plaintext] = score_text(plaintext)

    # Include the original frequency mapping
    plaintext = decrypt(ciphertext, base_key)
    candidates[plaintext] = score_text(plaintext)

    ranked = sorted(
        candidates.items(),
        key=lambda item: item[1],
        reverse=True
    )

    print("\nTOP", top_n, "POSSIBLE PLAINTEXTS")
    print("-" * 55)

    for rank,
    (plaintext, score) in enumerate(ranked[:top_n], 1):
        print(f"\nCandidate {rank}")
        print("Plaintext:", plaintext)
        print("Score:", score)


# Main program
ciphertext = input("Enter the ciphertext: ")

top_n = int(input("How many possible plaintexts? "))

if top_n <= 0:
    print("Enter a positive number.")
else:
    frequency_attack(ciphertext, top_n)
