from math import gcd

def encrypt(text, a, b):
    result = ""

    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            result += chr(c + ord('A'))
        else:
            result += ch

    return result


def decrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Invalid key: a must be coprime with 26")

    inverse = pow(a, -1, 26)
    result = ""

    for ch in text.upper():
        if ch.isalpha():
            c = ord(ch) - ord('A')
            p = (inverse * (c - b)) % 26
            result += chr(p + ord('A'))
        else:
            result += ch

    return result


plaintext = input("Enter plaintext: ")
a = int(input("Enter key a: "))
b = int(input("Enter key b: "))

if gcd(a, 26) != 1:
    print("Invalid key! GCD(a, 26) must be 1.")
else:
    ciphertext = encrypt(plaintext, a, b)
    recovered = decrypt(ciphertext, a, b)

    print("Ciphertext:", ciphertext)
    print("Decrypted text:", recovered)

# Demonstrate non-one-to-one mapping for a=2, b=3
print("\nInvalid key demonstration:")
print("E(0) =", (2 * 0 + 3) % 26)
print("E(13) =", (2 * 13 + 3) % 26)
