"""
des_lab.py - DES / 3DES teaching implementation (bit-list version).

The module contains the *correct* algorithm plus a set of switchable, deliberately
seeded bugs (names B1 ... B9).  A bug is active when its name is in the global set
BUGS.  This lets the debugging session in the report be reproduced step by step.
"""
import os

BUGS = set()            # active bug names, e.g. {"B3", "B5"}

# ---- standard DES tables (FIPS 46-3), positions are 1-based --------------------
IP = [58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3, 61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7]
FP = [40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27, 34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25]
E  = [32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
      16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1]
P  = [16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10, 2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17,9, 1,58,50,42,34,26,18, 10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
       63,55,47,39,31,23,15, 7,62,54,46,38,30,22, 14,6,61,53,45,37,29, 21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
       41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
SBOX = [
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

# ---- small helpers -----------------------------------------------------------
def bytes_to_bits(b):
    return [(byte >> (7 - i)) & 1 for byte in b for i in range(8)]

def bits_to_bytes(bits):
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))

def bits_to_int(bits):
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v

def int_to_bits(v, n):
    return [(v >> (n - 1 - i)) & 1 for i in range(n)]

def permute(bits, table):
    if "B3" in BUGS:                                   # BUG B3: table is 1-based, "% len" hides IndexError
        return [bits[i % len(bits)] for i in table]
    return [bits[i - 1] for i in table]                # FIX: convert 1-based table entry to 0-based index

# ---- key schedule --------------------------------------------------------------
_STALE = []                                            # used only by the buggy version (B2)

def key_schedule(key8, subkeys=None):
    """Return 16 round keys (each a list of 48 bits)."""
    if "B2" in BUGS:                                   # BUG B2: shared mutable default list survives between calls
        subkeys = _STALE
    else:
        subkeys = []                                   # FIX: new list for every call
    bits = permute(bytes_to_bits(key8), PC1)           # 64 -> 56 bits (parity bits dropped)
    c, d = bits[:28], bits[28:]
    new = []
    for rnd in range(16):
        n = 1 if "B4" in BUGS else SHIFTS[rnd]         # BUG B4: always rotates by one bit
        c, d = c[n:] + c[:n], d[n:] + d[:n]
        new.append(permute(c + d, PC2))                # 56 -> 48 bits
    subkeys.extend(new)
    return subkeys[:16]                                # buggy version returns the FIRST 16 ever computed

# ---- round function and block cipher ----------------------------------------
def feistel(r, subkey):
    x = [a ^ b for a, b in zip(permute(r, E), subkey)]          # expand 32->48 and XOR key
    out = []
    for i in range(8):
        chunk = x[6 * i:6 * i + 6]
        if "B5" in BUGS:                                         # BUG B5: wrong row/column bits
            row, col = chunk[0] * 2 + chunk[1], bits_to_int(chunk[2:])
        else:                                                    # FIX: row = outer bits, column = middle 4 bits
            row, col = chunk[0] * 2 + chunk[5], bits_to_int(chunk[1:5])
        out += int_to_bits(SBOX[i][row][col], 4)
    return permute(out, P)

def des_block(block8, subkeys, decrypt=False):
    bits = permute(bytes_to_bits(block8), IP)
    l, r = bits[:32], bits[32:]
    keys = subkeys if (not decrypt or "B7" in BUGS) else subkeys[::-1]   # BUG B7: decrypt must reverse key order
    for k in keys:
        l, r = r, [a ^ b for a, b in zip(l, feistel(r, k))]
    pre = (l + r) if "B6" in BUGS else (r + l)                         # BUG B6: final L/R swap missing
    return bits_to_bytes(permute(pre, FP))

def tdes_block(block8, k1, k2, k3, decrypt=False):
    """3DES.  Correct form is EDE: C = E_k3( D_k2( E_k1(P) ) )."""
    if "B8" in BUGS:                                   # BUG B8: E-E-E instead of E-D-E
        if not decrypt:
            return des_block(des_block(des_block(block8, k1), k2), k3)
        return des_block(des_block(des_block(block8, k3, True), k2, True), k1, True)
    if not decrypt:
        return des_block(des_block(des_block(block8, k1), k2, True), k3)
    return des_block(des_block(des_block(block8, k3, True), k2), k1, True)

# ---- padding and message level API -----------------------------------------
def pad(data):
    if "B9" in BUGS:                                   # BUG B9: zero padding is ambiguous
        return data + b"\x00" * (-len(data) % 8)
    n = 8 - len(data) % 8                              # FIX: PKCS#7
    return data + bytes([n]) * n

def unpad(data):
    if "B9" in BUGS:
        return data.rstrip(b"\x00")
    n = data[-1]
    if not 1 <= n <= 8 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]

def get_key(key=None):
    if "B1" in BUGS:                                   # BUG B1: key is regenerated randomly, caller's key ignored
        return os.urandom(8)
    return key

def des_ecb_encrypt(data, key=None):
    """Baseline (v0) encrypt.  NOTE: the key schedule is recomputed for every block (inefficiency I1)."""
    key = get_key(key)
    padded = pad(data)
    out = []
    for i in range(0, len(padded), 8):
        out.append(des_block(padded[i:i + 8], key_schedule(key)))
    return b"".join(out)

def des_ecb_decrypt(ct, key):
    sk = key_schedule(key)
    return unpad(b"".join(des_block(ct[i:i + 8], sk, True) for i in range(0, len(ct), 8)))

def tdes_ecb_encrypt(data, key24):
    ks = [key_schedule(key24[i:i + 8]) for i in (0, 8, 16)]
    p = pad(data)
    return b"".join(tdes_block(p[i:i + 8], *ks) for i in range(0, len(p), 8))

def tdes_ecb_decrypt(ct, key24):
    ks = [key_schedule(key24[i:i + 8]) for i in (0, 8, 16)]
    return unpad(b"".join(tdes_block(ct[i:i + 8], *ks, decrypt=True) for i in range(0, len(ct), 8)))


if __name__ == "__main__":                              # run:  python des_lab.py
    BUGS.clear()
    key, pt = bytes.fromhex("133457799BBCDFF1"), bytes.fromhex("0123456789ABCDEF")
    ct = des_block(pt, key_schedule(key))
    print("DES  key        :", key.hex().upper())
    print("DES  plaintext  :", pt.hex().upper())
    print("DES  ciphertext :", ct.hex().upper(), "(expected 85E813540F0AB405)")
    print("DES  decrypted  :", des_block(ct, key_schedule(key), True).hex().upper())
    k24 = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
    msg = b"PAY 5000 TO ACC1001"
    c3 = tdes_ecb_encrypt(msg, k24)
    print("3DES ciphertext :", c3.hex())
    print("3DES decrypted  :", tdes_ecb_decrypt(c3, k24))
