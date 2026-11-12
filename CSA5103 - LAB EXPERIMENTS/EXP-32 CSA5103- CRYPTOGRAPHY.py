from Crypto.PublicKey import DSA, RSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS, pkcs1_15

message = b"Digital Signature Demonstration"

# ---------------- DSA ----------------
dsa_key = DSA.generate(2048)

hash_obj = SHA256.new(message)

# FIPS 186-3 deterministic=False generates random k
dsa_signer = DSS.new(dsa_key, 'fips-186-3')

signature1 = dsa_signer.sign(hash_obj)

# Sign the same message again with a fresh random k
hash_obj = SHA256.new(message)
signature2 = dsa_signer.sign(hash_obj)

print("DSA Signature 1:", signature1.hex())
print("DSA Signature 2:", signature2.hex())
print("DSA signatures are different:",
      signature1 != signature2)

# ---------------- RSA ----------------
rsa_key = RSA.generate(2048)

hash_obj = SHA256.new(message)
rsa_signature1 = pkcs1_15.new(rsa_key).sign(hash_obj)

hash_obj = SHA256.new(message)
rsa_signature2 = pkcs1_15.new(rsa_key).sign(hash_obj)

print("\nRSA Signature 1:", rsa_signature1.hex())
print("RSA Signature 2:", rsa_signature2.hex())
print("RSA signatures are same:",
      rsa_signature1 == rsa_signature2)
