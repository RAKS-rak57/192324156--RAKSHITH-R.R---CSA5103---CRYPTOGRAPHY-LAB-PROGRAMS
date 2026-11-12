
from math import gcd

text = input("Enter plaintext: ")
a = int(input("Enter key a: "))
b = int(input("Enter key b: "))

if gcd(a, 26) != 1:
    print("Invalid key a! GCD(a, 26) must be 1.")
else:
    result = ""

    for ch in text:
        if ch.isupper():
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            result += chr(c + ord('A'))
        elif ch.islower():
            p = ord(ch) - ord('a')
            c = (a * p + b) % 26
            result += chr(c + ord('a'))
        else:
            result += ch

    print("Ciphertext:", result)
