"""Benchmarks for Part B/C of Question 1 (all numbers are measured on the machine that runs this script)."""
import os, time, json
import des_lab as lab, des_fast as fast
from debug_session import KEY, PT, EXPECT, ham
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

res = {}
# ---- effect of every bug on its own --------------------------------------------------
lab.BUGS.clear(); good_keys = lab.key_schedule(KEY)
iso = {}
for b in ["B2", "B3", "B4", "B5", "B6"]:
    lab.BUGS.clear(); lab.BUGS.add(b); lab._STALE.clear()
    try:
        ks = lab.key_schedule(KEY); nk = sum(1 for a, c in zip(ks, good_keys) if a != c)
        ct = lab.des_block(PT, ks)
    except Exception:
        nk, ct = -1, b"\0" * 8
    iso[b] = {"round_keys_wrong": nk, "bits_wrong": ham(ct, EXPECT)}
lab.BUGS.clear(); lab._STALE.clear()
res["isolated"] = iso

# ---- throughput ---------------------------------------------------------------------
MB = 1024 * 1024
def best(fn, n=3):
    t = []
    for _ in range(n):
        s = time.perf_counter(); fn(); t.append(time.perf_counter() - s)
    return min(t)
k24 = os.urandom(24); k8 = k24[:8]
d10 = os.urandom(10 * MB)
tp = {}
sample = os.urandom(16 * 1024)
t = best(lambda: lab.des_ecb_encrypt(sample, k8), 1); tp["v0 DES (bit lists, key schedule per block)"] = len(sample) / MB / t
sample3 = os.urandom(8 * 1024)
t = best(lambda: lab.tdes_ecb_encrypt(sample3, k24), 1); tp["v0 3DES (bit lists)"] = len(sample3) / MB / t
s1 = os.urandom(512 * 1024)
t = best(lambda: fast.ecb_v1(s1, k8), 1); tp["v1 DES (integers + SP tables)"] = len(s1) / MB / t
t = best(lambda: fast.des_ecb_np(d10, k8), 2); tp["v2 DES (NumPy, block-parallel)"] = 10 / t; res["v2_des_10mb_s"] = t
t = best(lambda: fast.tdes_ecb_np(d10, k24), 2); tp["v2 3DES (NumPy, block-parallel)"] = 10 / t; res["v2_3des_10mb_s"] = t
t = best(lambda: fast.tdes_ctr_np(d10, k24, 1), 2); tp["v2 3DES-CTR (NumPy)"] = 10 / t
def ossl(alg, mode):
    c = Cipher(alg, mode).encryptor(); return lambda: (c.update(d10), c.finalize())
tp["OpenSSL 3DES-ECB"] = 10 / best(lambda: Cipher(TripleDES(k24), modes.ECB()).encryptor().update(d10))
tp["OpenSSL AES-128-CBC"] = 10 / best(lambda: Cipher(algorithms.AES(k24[:16]), modes.CBC(os.urandom(16))).encryptor().update(d10))
g128, g256 = AESGCM(AESGCM.generate_key(128)), AESGCM(AESGCM.generate_key(256))
tp["OpenSSL AES-128-GCM"] = 10 / best(lambda: g128.encrypt(os.urandom(12), d10, None))
tp["OpenSSL AES-256-GCM"] = 10 / best(lambda: g256.encrypt(os.urandom(12), d10, None))
res["throughput_MBps"] = tp
res["extrapolated_10MB_s"] = {k: 10 / v for k, v in tp.items()}
# ---- correctness of every optimised path versus OpenSSL ------------------------------
x = os.urandom(8 * 2048); ref3 = Cipher(TripleDES(k24), modes.ECB()).encryptor().update(x); ref1 = Cipher(TripleDES(k8), modes.ECB()).encryptor().update(x)
res["checks"] = {"v1 DES == OpenSSL": fast.ecb_v1(x, k8) == ref1, "v2 DES == OpenSSL": fast.des_ecb_np(x, k8) == ref1,
                 "v2 3DES == OpenSSL": fast.tdes_ecb_np(x, k24) == ref3, "v2 3DES decrypt round-trip": fast.tdes_ecb_np(ref3, k24, True) == x,
                 "v0 3DES == v2 3DES": lab.tdes_ecb_encrypt(x[:512], k24)[:512] == fast.tdes_ecb_np(x[:512], k24)}
json.dump(res, open("bench_des.json", "w"), indent=1)
print(json.dumps(res, indent=1))
