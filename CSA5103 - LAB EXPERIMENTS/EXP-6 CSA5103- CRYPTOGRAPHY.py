
from collections import Counter
from math import gcd

ciphertext = input("Enter ciphertext: ").upper()

# Display letter frequencies
letters = [ch for ch in ciphertext if ch.isalpha()]
frequency = Counter(letters)

print("Letter frequencies:")
for letter, count in frequency.most_common():
    print(letter, ":", count)

# Given: B is assumed to represent E, and U represents T
c1, p1 = ord('B') - ord('A'), ord('E') - ord('A')
c2, p2 = ord('U') - ord('A'), ord('T') - ord('A')

# From C = (aP + b) mod 26
possible_keys = []

for a in range(1, 26):
    if gcd(a, 26) == 1:
        b = (c1 - a * p1) % 26

        if (a * p2 + b) % 26 == c2:
            possible_keys.append((a, b))

for a, b in possible_keys:
    inverse = pow(a, -1, 26)
    result = ""

    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch) - ord('A')
            p = (inverse * (c - b)) % 26
            result += chr(p + ord('A'))
        else:
            result += ch

    print("Candidate key:", a, b)
    print("Candidate plaintext:", result)
5
