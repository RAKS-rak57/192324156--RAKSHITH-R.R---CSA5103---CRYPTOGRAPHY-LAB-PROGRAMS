
import math

e = 31
n = 3599

# Find prime factors
for p in range(2, int(math.sqrt(n)) + 1):
    if n % p == 0:
        q = n // p
        break

# Calculate Euler's totient
phi = (p - 1) * (q - 1)

# Calculate private key
d = pow(e, -1, phi)

print("RSA PRIVATE KEY GENERATION")
print("p =", p)
print("q =", q)
print("n =", n)
print("Phi(n) =", phi)
print("Public key (e, n) =", (e, n))
print("Private key (d, n) =", (d, n))
