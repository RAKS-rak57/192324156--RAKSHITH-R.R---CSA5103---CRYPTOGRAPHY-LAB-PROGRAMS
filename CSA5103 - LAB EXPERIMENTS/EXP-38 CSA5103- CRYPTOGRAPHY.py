import numpy as np
from math import gcd

MOD = 26

def matrix_inverse_mod26(matrix):
    det = round(np.linalg.det(matrix)) % MOD

    if gcd(det, MOD) != 1:
        raise ValueError("Plaintext matrix is not invertible modulo 26")

    det_inverse = pow(det, -1, MOD)

    # For a 2x2 matrix
    adj = np.array([
        [matrix[1, 1], -matrix[0, 1]],
        [-matrix[1, 0], matrix[0, 0]]
    ])

    return (det_inverse * adj) % MOD


def text_to_numbers(text):
    return [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()]


# Known plaintext and corresponding ciphertext
plaintext = input("Enter known plaintext (4 letters): ")
ciphertext = input("Enter corresponding ciphertext (4 letters): ")

P_values = text_to_numbers(plaintext)
C_values = text_to_numbers(ciphertext)

if len(P_values) != 4 or len(C_values) != 4:
    raise ValueError("Enter exactly 4 alphabetic characters for each text")

# Arrange into 2x2 matrices, with each pair as a column
P = np.array(P_values).reshape(2, 2).T
C = np.array(C_values).reshape(2, 2).T

# Recover key matrix
P_inverse = matrix_inverse_mod26(P)
K = (C @ P_inverse) % MOD

print("\nPlaintext matrix:")
print(P)

print("\nCiphertext matrix:")
print(C)

print("\nRecovered key matrix:")
print(K)

# Verify the recovered key
print("\nVerification:")
print((K @ P) % MOD)
print("Matches ciphertext:", np.array_equal((K @ P) % MOD, C))
