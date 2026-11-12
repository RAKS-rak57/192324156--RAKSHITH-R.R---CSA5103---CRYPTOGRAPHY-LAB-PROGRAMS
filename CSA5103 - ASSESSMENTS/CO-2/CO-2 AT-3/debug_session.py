"""Reproduces the DES/3DES debugging session: bugs are removed one at a time and the test-suite is re-run."""
import os, json
import des_lab as lab
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

KEY  = bytes.fromhex("133457799BBCDFF1")      # FIPS / textbook worked-example key
PT   = bytes.fromhex("0123456789ABCDEF")
EXPECT = bytes.fromhex("85E813540F0AB405")    # known ciphertext for the pair above
K1_EXPECT = 0x1B02EFFC7072                    # known first round key of the worked example
MSG  = b"PAY 5000 TO ACC1001"
K24  = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")

def ham(a, b):
    return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")

def t_determinism():            # 3 separate program runs (module state reset each time) must agree
    outs = set()
    for _ in range(3):
        lab._STALE.clear()                     # simulates starting a fresh process
        outs.add(lab.des_ecb_encrypt(MSG, KEY))
    return len(outs) == 1
def t_key_state():              # two different keys must give two different ciphertexts
    lab._STALE.clear()
    a = lab.des_ecb_encrypt(MSG, KEY); b = lab.des_ecb_encrypt(MSG, bytes(range(8)))
    return a != b
def t_perm_inverse():           # FP(IP(x)) must give x back
    x = lab.bytes_to_bits(PT)
    return lab.permute(lab.permute(x, lab.IP), lab.FP) == x
def t_round_key():
    lab._STALE.clear(); return lab.bits_to_int(lab.key_schedule(KEY)[0]) == K1_EXPECT
def t_fips():
    lab._STALE.clear(); return lab.des_block(PT, lab.key_schedule(KEY)) == EXPECT
def t_roundtrip():
    lab._STALE.clear(); sk = lab.key_schedule(KEY); return lab.des_block(lab.des_block(PT, sk), sk, True) == PT
def t_3des_openssl():
    lab._STALE.clear()
    try:
        ct = lab.tdes_ecb_encrypt(MSG, K24)
    except Exception:
        return False
    e = Cipher(TripleDES(K24), modes.ECB()).encryptor()
    return ct == e.update(lab.pad(MSG) if "B9" not in lab.BUGS else MSG + b"\x00" * (-len(MSG) % 8)) + e.finalize()
def t_padding():
    lab._STALE.clear(); m = b"AB\x00\x00"
    try:
        return lab.tdes_ecb_decrypt(lab.tdes_ecb_encrypt(m, K24), K24) == m
    except Exception:
        return False

TESTS = [("T1 same input -> same ciphertext", t_determinism), ("T2 key A and key B differ", t_key_state),
         ("T3 FP(IP(x)) = x", t_perm_inverse), ("T4 round key K1 = 1B02EFFC7072", t_round_key),
         ("T5 FIPS vector = 85E813540F0AB405", t_fips), ("T6 decrypt(encrypt(x)) = x", t_roundtrip),
         ("T7 3DES = OpenSSL 3DES", t_3des_openssl), ("T8 padding round-trip", t_padding)]
ORDER = [("start (all 9 bugs present)", None), ("fix B1 (random key)", "B1"), ("fix B2 (shared list)", "B2"),
         ("fix B3 (permute index)", "B3"), ("fix B4 (shift table)", "B4"), ("fix B5 (S-box row/col)", "B5"),
         ("fix B6 (final swap)", "B6"), ("fix B7 (decrypt key order)", "B7"), ("fix B8 (EDE order)", "B8"), ("fix B9 (PKCS#7)", "B9")]
if __name__ == "__main__":
    lab.BUGS.clear(); lab.BUGS.update({f"B{i}" for i in range(1, 10)})
    rows = []
    for name, fix in ORDER:
        if fix: lab.BUGS.discard(fix)
        res = [bool(t()) for _, t in TESTS]
        lab._STALE.clear()
        try: ct = lab.des_block(PT, lab.key_schedule(KEY))
        except Exception as e: ct = b"\x00" * 8
        rows.append({"step": name, "tests": res, "passed": sum(res), "fips_out": ct.hex(), "bit_errors": ham(ct, EXPECT)})
        print(f"{name:32s} passed {sum(res)}/8  FIPS-out {ct.hex()}  wrong bits {ham(ct, EXPECT)}")
    # B1 symptom: five runs of the ORIGINAL program give five different ciphertexts
    lab.BUGS.clear(); lab.BUGS.update({"B1"})
    runs = []
    for _ in range(3):
        lab._STALE.clear(); runs.append(lab.des_ecb_encrypt(MSG, KEY).hex())
    lab.BUGS.clear(); lab._STALE.clear()
    pre = lab.bits_to_int(lab.permute(lab.permute(lab.bytes_to_bits(PT), lab.IP), lab.FP))
    out = {"rows": rows, "tests": [t for t, _ in TESTS], "b1_runs": runs}
    json.dump(out, open("debug.json", "w"), indent=1)
    print("B1 runs:", *runs, sep="\n  ")
