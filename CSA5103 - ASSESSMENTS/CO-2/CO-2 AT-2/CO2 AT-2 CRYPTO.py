import os, time, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
 
res = {}
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
iv  = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
# financial records: 16-byte blocks
blk = lambda s: s.encode().ljust(16)[:16]
blocks = [blk("PAY ACC1001 5000"), blk("PAY ACC1001 5000"), blk("PAY ACC2002 9000"), blk("PAY ACC1001 5000")]
pt = b"".join(blocks)
def enc(mode):
    c = Cipher(algorithms.AES(key), mode).encryptor(); return c.update(pt) + c.finalize()
ecb = enc(modes.ECB()); cbc = enc(modes.CBC(iv)); ctr = enc(modes.CTR(iv))
split = lambda b: [b[i:i+16].hex() for i in range(0, len(b), 16)]
res["blocks"] = [b.decode().strip() for b in blocks]
res["ecb"] = split(ecb); res["cbc"] = split(cbc); res["ctr"] = split(ctr)
nonce = bytes.fromhex("00112233445566778899aabb")
g = AESGCM(key).encrypt(nonce, pt, b"txn-header")
res["gcm_ct"] = split(g[:-16]); res["gcm_tag"] = g[-16:].hex()
# tamper test for ECB (swap block 3 and 1 -> still decrypts) vs GCM (rejects)
sw = ecb[32:48] + ecb[16:32] + ecb[0:16] + ecb[48:]
d = Cipher(algorithms.AES(key), modes.ECB()).decryptor(); swp = d.update(sw) + d.finalize()
res["ecb_swapped_plain"] = [swp[i:i+16].decode().strip() for i in range(0, 64, 16)]
bad = bytearray(g); bad[5] ^= 1
try: AESGCM(key).decrypt(nonce, bytes(bad), b"txn-header"); res["gcm_tamper"] = "accepted"
except Exception as e: res["gcm_tamper"] = "REJECTED (InvalidTag)"
# repeats count
res["ecb_dup"] = len(split(ecb)) - len(set(split(ecb))); res["cbc_dup"] = len(split(cbc)) - len(set(split(cbc)))
 
# ---- IoT benchmark ----
def timeit(f, n):
    t = time.perf_counter()
    for _ in range(n): f()
    return (time.perf_counter() - t) / n * 1000
msg = b"temperature=24.5C;door=locked"
rk = rsa.generate_private_key(65537, 2048); rpub = rk.public_key()
rsig = rk.sign(msg, padding.PKCS1v15(), hashes.SHA256())
ek = ec.generate_private_key(ec.SECP256R1()); epub = ek.public_key()
esig = ek.sign(msg, ec.ECDSA(hashes.SHA256()))
xa = x25519.X25519PrivateKey.generate(); xb = x25519.X25519PrivateKey.generate()
b = {}
b["RSA-2048 key generation"] = timeit(lambda: rsa.generate_private_key(65537, 2048), 5)
b["ECC P-256 key generation"] = timeit(lambda: ec.generate_private_key(ec.SECP256R1()), 200)
b["RSA-2048 sign (private key)"] = timeit(lambda: rk.sign(msg, padding.PKCS1v15(), hashes.SHA256()), 100)
b["ECDSA P-256 sign (private key)"] = timeit(lambda: ek.sign(msg, ec.ECDSA(hashes.SHA256())), 200)
b["RSA-2048 verify"] = timeit(lambda: rpub.verify(rsig, msg, padding.PKCS1v15(), hashes.SHA256()), 200)
b["ECDSA P-256 verify"] = timeit(lambda: epub.verify(esig, msg, ec.ECDSA(hashes.SHA256())), 200)
res["bench"] = b
res["sizes"] = {"rsa_pub": len(rpub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                "ecc_pub": len(epub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                "rsa_sig": len(rsig), "ecdsa_sig": len(esig), "x25519_pub": 32}
# ---- smart-home session: X25519 + HKDF + AES-GCM ----
sa = xa.exchange(xb.public_key()); sb = xb.exchange(xa.public_key())
assert sa == sb
k = HKDF(hashes.SHA256(), 16, None, b"smart-home session").derive(sa)
n2 = os.urandom(12)
c2 = AESGCM(k).encrypt(n2, msg, b"hub->lock")
p2 = AESGCM(k).decrypt(n2, c2, b"hub->lock")
res["session"] = {"shared_equal": sa == sb, "key_hex": k.hex(), "ct_len": len(c2), "pt_len": len(msg), "roundtrip": p2.decode()}
json.dump(res, open("results.json", "w"), indent=1)
print(json.dumps(res, indent=1))
