
import math

n = int(input("Enter RSA modulus n: "))
e = int(input("Enter public key e: "))
m = int(input("Enter known plaintext block: "))

# Find common factor
p = math.gcd(m, n)

print("\nGCD(m, n) =", p)

if p > 1 and p < n:
    q = n // p

    if p * q == n:
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)

        print("Prime factor p =", p)
        print("Prime factor q =", q)
        print("Phi(n) =", phi)
        print("Private key (d, n) =", (d, n))
    else:
        print("Factorization requires further analysis.")
else:
    print("No non-trivial factor found.")
