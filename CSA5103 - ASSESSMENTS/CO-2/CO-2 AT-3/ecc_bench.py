"""Benchmarks for Question 5, Parts B and C (all numbers measured on the machine running this script)."""
import time, json, secrets, os
import ecc_lab as e
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes

e.BUGS.clear()
C = e.P256
def timeit(f, n):
    s = time.perf_counter()
    for _ in range(n): f()
    return (time.perf_counter() - s) / n * 1000            # milliseconds
def rand_bits(b): return secrets.randbits(b - 1) | (1 << (b - 1))
R = {}
# ---- scaling with the size of k ---------------------------------------------------------
naive_bits = list(range(4, 16))
R["naive"] = {"bits": naive_bits, "ms": [timeit(lambda b=b: e.mul_naive(C, rand_bits(b), C.G), 1) for b in naive_bits]}
bits = [8, 32, 64, 96, 128, 160, 192, 224, 256]
R["affine"] = {"bits": bits, "ms": [timeit(lambda b=b: e.mul_double_and_add(C, rand_bits(b), C.G), 4) for b in bits]}
R["jacobian"] = {"bits": bits, "ms": [timeit(lambda b=b: e.mul_jacobian(C, rand_bits(b), C.G), 6) for b in bits]}
# ---- full 256-bit scalar multiplication --------------------------------------------------
ks = [rand_bits(256) for _ in range(8)]
full = {}
full["Naive repeated addition (estimated: 2^255 steps)"] = None
full["Double-and-add, affine"] = timeit(lambda: e.mul_double_and_add(C, ks[0], C.G), 6)
full["Double-and-add, Jacobian"] = timeit(lambda: e.mul_jacobian(C, ks[1], C.G), 10)
full["Montgomery ladder, Jacobian"] = timeit(lambda: e.mul_ladder(C, ks[2], C.G), 10)
sk = ec.derive_private_key(ks[3] % C.n, ec.SECP256R1())
full["OpenSSL (C code)"] = timeit(lambda: ec.derive_private_key(ks[3] % C.n, ec.SECP256R1()), 300)
R["full256_ms"] = full
est_step = R["naive"]["ms"][-1] / (2 ** naive_bits[-1])
R["naive_ms_per_add"] = est_step
R["naive_256_years"] = est_step / 1000 * 2 ** 255 / (3600 * 24 * 365)
assert e.mul_double_and_add(C, ks[0], C.G) == e.mul_jacobian(C, ks[0], C.G) == e.mul_ladder(C, ks[0], C.G)
# ---- RSA-2048 versus ECC P-256 in the same Python loop style ----------------------------
key = rsa.generate_private_key(65537, 2048); nums = key.private_numbers(); pn = nums.public_numbers
n, d, p_, q_, dp, dq, qinv = pn.n, nums.d, nums.p, nums.q, nums.dmp1, nums.dmq1, nums.iqmp
def modexp(b, ex, m):                                       # plain square-and-multiply, written in Python
    r = 1
    for bit in bin(ex)[2:]:
        r = r * r % m
        if bit == "1": r = r * b % m
    return r
def rsa_plain(c): return modexp(c, d, n)
def rsa_crt(c):
    m1, m2 = modexp(c % p_, dp, p_), modexp(c % q_, dq, q_)
    return m2 + (qinv * (m1 - m2) % p_) * q_
msg = secrets.randbelow(n); ct = pow(msg, 65537, n)
assert rsa_plain(ct) == msg == rsa_crt(ct) == pow(ct, d, n)
pure = {}
pure["RSA-2048 private op, square-and-multiply"] = timeit(lambda: rsa_plain(ct), 3)
pure["RSA-2048 private op, with CRT"] = timeit(lambda: rsa_crt(ct), 6)
pure["ECC P-256 scalar mult, Jacobian"] = full["Double-and-add, Jacobian"]
R["pure_python_ms"] = pure
# ---- OpenSSL (C) level ---------------------------------------------------------------
oss = {}
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
ctr = key.public_key().encrypt(b"session key", oaep)
oss["RSA-2048 decrypt (private key)"] = timeit(lambda: key.decrypt(ctr, oaep), 200)
peer = ec.generate_private_key(ec.SECP256R1()).public_key(); me = ec.generate_private_key(ec.SECP256R1())
oss["ECDH P-256 (private key op)"] = timeit(lambda: me.exchange(ec.ECDH(), peer), 400)
oss["RSA-2048 key generation"] = timeit(lambda: rsa.generate_private_key(65537, 2048), 4)
oss["ECC P-256 key generation"] = timeit(lambda: ec.generate_private_key(ec.SECP256R1()), 400)
R["openssl_ms"] = oss
# ---- cost model: field multiplications ------------------------------------------------
dbl, add = 10, 16                                            # field mults per Jacobian doubling / addition (approx.)
ecc_ops = 255 * dbl + 128 * add
rsa_plain_ops = 2048 + 1024; rsa_crt_ops = 2 * (1024 + 512)
R["model"] = {"ecc_field_mults": ecc_ops, "ecc_cost": ecc_ops * 256 ** 2, "rsa_plain_cost": rsa_plain_ops * 2048 ** 2, "rsa_crt_cost": rsa_crt_ops * 1024 ** 2}
R["model"]["ratio_plain"] = R["model"]["rsa_plain_cost"] / R["model"]["ecc_cost"]
R["model"]["ratio_crt"] = R["model"]["rsa_crt_cost"] / R["model"]["ecc_cost"]
R["sizes"] = {"ecc_pub": 32, "ecc_pub_uncompressed": 65, "rsa_pub": 256, "ecdsa_sig": 64, "rsa_sig": 256}
json.dump(R, open("ecc_bench.json", "w"), indent=1)
print(json.dumps({k: v for k, v in R.items() if k not in ("naive", "affine", "jacobian")}, indent=1))
print("naive", [round(x, 2) for x in R["naive"]["ms"]]); print("aff", [round(x, 2) for x in R["affine"]["ms"]]); print("jac", [round(x, 2) for x in R["jacobian"]["ms"]])
