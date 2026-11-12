
import math

def hill_encrypt(text, key):
    text = ''.join(c for c in text.upper() if c.isalpha())

    if len(text) % 2 != 0:
        text += 'X'

    result = ''

    for i in range(0, len(text), 2):
        a = ord(text[i]) - ord('A')
        b = ord(text[i + 1]) - ord('A')

        c1 = (key[0][0] * a + key[0][1] * b) % 26
        c2 = (key[1][0] * a + key[1][1] * b) % 26

        result += chr(c1 + 65) + chr(c2 + 65)

    return result


def hill_decrypt(cipher, inverse_key):
    result = ''

    for i in range(0, len(cipher), 2):
        a = ord(cipher[i]) - ord('A')
        b = ord(cipher[i + 1]) - ord('A')

        p1 = (inverse_key[0][0] * a +
              inverse_key[0][1] * b) % 26
        p2 = (inverse_key[1][0] * a +
              inverse_key[1][1] * b) % 26

        result += chr(p1 + 65) + chr(p2 + 65)

    return result


key = [[9, 4], [5, 7]]

# Inverse of the key matrix modulo 26
det = (9 * 7 - 4 * 5) % 26
det_inverse = pow(det, -1, 26)

inverse_key = [
    [(det_inverse * 7) % 26, (det_inverse * -4) % 26],
    [(det_inverse * -5) % 26, (det_inverse * 9) % 26]
]

plaintext = input("Enter plaintext: ")

ciphertext = hill_encrypt(plaintext, key)
decrypted = hill_decrypt(ciphertext, inverse_key)

print("\nCiphertext:", ciphertext)
print("Decrypted text:", decrypted)
