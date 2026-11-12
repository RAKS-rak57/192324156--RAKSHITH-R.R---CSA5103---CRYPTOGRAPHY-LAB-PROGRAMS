# Diffie-Hellman Key Exchange

q = 23       # Public prime number
a = 5        # Public base

# Private secret numbers
alice_secret = 6
bob_secret = 15

# Public values exchanged
alice_public = pow(a, alice_secret, q)
bob_public = pow(a, bob_secret, q)

# Shared secret keys
alice_key = pow(bob_public, alice_secret, q)
bob_key = pow(alice_public, bob_secret, q)

print("Public prime q:", q)
print("Public base a:", a)

print("\nAlice's public value:", alice_public)
print("Bob's public value:", bob_public)

print("\nAlice's shared key:", alice_key)
print("Bob's shared key:", bob_key)

if alice_key == bob_key:
    print("Key exchange successful!")
else:
    print("Key exchange failed!")

# Alternative: sending x^a instead of a^x
alice_alt = alice_secret ** a
bob_alt = bob_secret ** a

print("\nAlternative values:")
print("Alice sends xA^a:", alice_alt)
print("Bob sends xB^a:", bob_alt)
