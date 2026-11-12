
import math

def recover_key(plain, cipher):
    p = [[ord(plain[0])-65, ord(plain[2])-65],
         [ord(plain[1])-65, ord(plain[3])-65]]

    c = [[ord(cipher[0])-65, ord(cipher[2])-65],
         [ord(cipher[1])-65, ord(cipher[3])-65]]

    det = (p[0][0]*p[1][1] - p[0][1]*p[1][0]) % 26

    if math.gcd(det, 26) != 1:
        print("Plaintext matrix is not invertible!")
        return

    inv_det = pow(det, -1, 26)

    inv = [[p[1][1], -p[0][1]],
           [-p[1][0], p[0][0]]]

    inv = [[(x * inv_det) % 26 for x in row] for row in inv]

    key = [[sum(c[i][k] * inv[k][j] for k in range(2)) % 26
            for j in range(2)] for i in range(2)]

    print("Recovered key matrix:")
    for row in key:
        print(*row)


plain = input("Enter 4 plaintext letters: ").upper().replace(" ", "")
cipher = input("Enter corresponding 4 ciphertext letters: ").upper().replace(" ", "")

if len(plain) == 4 and len(cipher) == 4 and plain.isalpha() and cipher.isalpha():
    recover_key(plain, cipher)
else:
    print("Enter exactly 4 letters for each input.")
