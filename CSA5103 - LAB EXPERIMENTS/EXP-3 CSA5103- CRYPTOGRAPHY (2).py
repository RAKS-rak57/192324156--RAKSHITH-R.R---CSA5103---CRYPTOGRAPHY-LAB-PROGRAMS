
import string

text = input("Enter plaintext: ")
key = input("Enter 26-letter substitution key: ").upper()

alphabet = string.ascii_uppercase

if len(key) != 26 or set(key) != set(alphabet):
    print("Invalid key! Enter all 26 letters exactly once.")
else:
    mapping = dict(zip(alphabet, key))
    result = ""

    for ch in text:
        if ch.isupper():
            result += mapping.get(ch, ch)
        elif ch.islower():
            result += mapping.get(ch.upper(), ch).lower()
        else:
            result += ch

    print("Ciphertext:", result)
