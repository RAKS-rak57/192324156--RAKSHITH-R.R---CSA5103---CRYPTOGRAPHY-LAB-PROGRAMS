from math import gcd

# RSA key generation
p = 61
q = 53
n = p * q
phi = (p - 1) * (q - 1)

# Original keys
e1 = 17
d1 = pow(e1, -1, phi)

print("Original public key:", (e1, n))
print("Original private key:", (d1, n))

# Bob's private key is leaked
print("\nBob's private key has been leaked!")

# Bob generates a new key pair but keeps the same modulus
e2 = 7
d2 = pow(e2, -1, phi)

print("New public key:", (e2, n))
print("New private key:", (d2, n))

# Attacker factors the unchanged modulus (small example)
for i in range(2, int(n ** 0.5) + 1):
    if n % i == 0:
        p_found = i
        q_found = n // i
        break

# Attacker calculates the new private key
phi_found = (p_found - 1) * (q_found - 1)
d_attacker = pow(e2, -1, phi_found)

print("\nAttacker factors n:", p_found, "*", q_found)
print("Attacker calculates new private key:", (d_attacker, n))

if d_attacker == d2:
    print("New private key is also compromised!")
