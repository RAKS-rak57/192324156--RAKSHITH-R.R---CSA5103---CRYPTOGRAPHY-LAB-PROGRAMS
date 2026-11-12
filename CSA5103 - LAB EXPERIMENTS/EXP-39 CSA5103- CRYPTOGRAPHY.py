from collections import Counter

# Standard English letter frequencies (percentages)
english_freq = {
    'A': 8.167, 'B': 1.492, 'C': 2.782,
    'D': 4.253, 'E': 12.702, 'F': 2.228,
    'G': 2.015, 'H': 6.094, 'I': 6.966,
    'J': 0.153, 'K': 0.772, 'L': 4.025,
    'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758,
    'V': 0.978, 'W': 2.360, 'X': 0.150,
    'Y': 1.974, 'Z': 0.074
}

# Decrypt additive cipher
def decrypt(text, shift):
    result = ""

    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            value = (ord(ch) - base - shift) % 26
            result += chr(value + base)
        else:
            result += ch

    return result


# Calculate chi-square frequency score
def frequency_score(text):
    letters = [ch.upper() for ch in text if ch.isalpha()]
    total = len(letters)

    if total == 0:
        return float('inf')

    counts = Counter(letters)
    score = 0

    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        observed = counts.get(letter, 0)
        expected = english_freq[letter] * total / 100

        score += ((observed - expected) ** 2) / expected

    return score


# Read ciphertext
ciphertext = input("Enter encrypted message: ")
top_n = int(input("Enter number of possible plaintexts: "))

# Test all 26 shifts
candidates = []

for shift in range(26):
    plaintext = decrypt(ciphertext, shift)
    score = frequency_score(plaintext)

    candidates.append((score, shift, plaintext))

# Lowest chi-square score = better frequency match
candidates.sort(key=lambda item: item[0])

# Display top candidates
print("\nTOP", top_n, "POSSIBLE PLAINTEXTS")

for i, (score, shift, plaintext) in enumerate(
    candidates[:max(0, min(top_n, 26))], 1
):
    print("\nCandidate:", i)
    print("Decryption shift:", shift)
    print("Frequency score:", round(score, 3))
    print("Plaintext:", plaintext)
