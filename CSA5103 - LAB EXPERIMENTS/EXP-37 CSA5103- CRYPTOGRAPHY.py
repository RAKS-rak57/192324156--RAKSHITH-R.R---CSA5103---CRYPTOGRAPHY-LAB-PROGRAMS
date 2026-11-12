from collections import Counter

# Common English letter frequency order
english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# Common English letter combinations
common_patterns = [
    "TH", "HE", "IN", "ER", "AN", "RE",
    "ON", "AT", "EN", "ND", "THE", "AND",
    "ING", "ION", "ENT", "HER", "FOR",
    "THA", "NTH", "INT", "ERE", "TIO"
]


# Calculate frequency score
def calculate_score(text):
    text = text.upper()

    score = 0

    for pattern in common_patterns:
        score += text.count(pattern) * len(pattern)

    return score


# Generate possible plaintext
def generate_plaintext(ciphertext, mapping):
    result = ""

    for ch in ciphertext.upper():
        if ch.isalpha():
            result += mapping.get(ch, ch)
        else:
            result += ch

    return result


# Read ciphertext
ciphertext = input("Enter encrypted message: ").upper()

top_n = int(input("Enter number of possible plaintexts: "))

# Count ciphertext letter frequencies
frequency = Counter(ch for ch in ciphertext if ch.isalpha())

# Sort cipher letters by frequency
sorted_cipher = [
    letter for letter, count in frequency.most_common()
]

# Add missing letters
for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    if letter not in sorted_cipher:
        sorted_cipher.append(letter)

candidates = []

# Generate 26 possible frequency mappings
for shift in range(26):

    rotated_english = (
        english_order[shift:] + english_order[:shift]
    )

    mapping = {}

    for i in range(26):
        mapping[sorted_cipher[i]] = rotated_english[i]

    plaintext = generate_plaintext(ciphertext, mapping)

    score = calculate_score(plaintext)

    candidates.append((score, plaintext))

# Sort candidates by score
candidates.sort(reverse=True)

# Remove duplicate plaintexts
unique_candidates = []
seen = set()

for score, plaintext in candidates:
    if plaintext not in seen:
        unique_candidates.append((score, plaintext))
        seen.add(plaintext)

# Display top candidates
print("\nTOP", top_n, "POSSIBLE PLAINTEXTS")

for i, (score, plaintext) in enumerate(
    unique_candidates[:top_n], 1
):
    print("\nCandidate", i)
    print("Score:", score)
    print("Plaintext:", plaintext)
