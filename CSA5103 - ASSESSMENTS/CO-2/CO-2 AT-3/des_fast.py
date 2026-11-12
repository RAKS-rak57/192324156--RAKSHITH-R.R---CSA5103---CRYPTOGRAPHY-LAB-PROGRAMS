"""
des_fast.py - optimised DES / 3DES.
  v1 : 64-bit integers + pre-computed S-box/P tables (SP tables) + key schedule computed once
  v2 : v1 vectorised with NumPy so that millions of blocks are processed per call (ECB / CTR style)
"""
import struct
import numpy as np
import des_lab as lab

lab.BUGS.clear()
M32 = 0xFFFFFFFF

def _perm_int(value, table, n_in):
    return lab.bits_to_int(lab.permute(lab.int_to_bits(value, n_in), table))

# SP[i][x]: S-box i applied to 6-bit x, then the P permutation (a 32-bit result)
SP = [[_perm_int(lab.SBOX[i][((x >> 5) << 1) | (x & 1)][(x >> 1) & 15] << (28 - 4 * i), lab.P, 32)
       for x in range(64)] for i in range(8)]

def _byte_tables(table):
    """8 x 256 table: permutation of a 64-bit value done one byte at a time."""
    return [[_perm_int(b << (56 - 8 * j), table, 64) for b in range(256)] for j in range(8)]
IPT, FPT = _byte_tables(lab.IP), _byte_tables(lab.FP)

def prepare_keys(key8):
    """Round keys as eight 6-bit groups per round (computed ONCE per key)."""
    return [[(lab.bits_to_int(k) >> (42 - 6 * i)) & 63 for i in range(8)] for k in lab.key_schedule(key8)]

# ------------------------------ v1 : pure Python, integers ------------------------------
def _perm64(x, T):
    return (T[0][x >> 56] | T[1][(x >> 48) & 255] | T[2][(x >> 40) & 255] | T[3][(x >> 32) & 255] |
            T[4][(x >> 24) & 255] | T[5][(x >> 16) & 255] | T[6][(x >> 8) & 255] | T[7][x & 255])

def block_v1(x, sks):
    x = _perm64(x, IPT)
    l, r = x >> 32, x & M32
    s0, s1, s2, s3, s4, s5, s6, s7 = SP
    for g in sks:
        t = ((r & 1) << 33) | (r << 1) | (r >> 31)            # 32 -> 34 bits, 6-bit groups are slices of t
        f = (s0[((t >> 28) & 63) ^ g[0]] ^ s1[((t >> 24) & 63) ^ g[1]] ^ s2[((t >> 20) & 63) ^ g[2]] ^
             s3[((t >> 16) & 63) ^ g[3]] ^ s4[((t >> 12) & 63) ^ g[4]] ^ s5[((t >> 8) & 63) ^ g[5]] ^
             s6[((t >> 4) & 63) ^ g[6]] ^ s7[(t & 63) ^ g[7]])
        l, r = r, l ^ f
    return _perm64((r << 32) | l, FPT)

def ecb_v1(data, key8, decrypt=False):
    sks = prepare_keys(key8)
    sks = sks[::-1] if decrypt else sks
    n = len(data) // 8
    words = struct.unpack(">%dQ" % n, data)
    return struct.pack(">%dQ" % n, *[block_v1(w, sks) for w in words])

# ------------------------------ v2 : NumPy, many blocks at once ------------------------------
U = np.uint64
SPN = [np.array(t, dtype=np.uint64) for t in SP]
IPN = [np.array(t, dtype=np.uint64) for t in IPT]
FPN = [np.array(t, dtype=np.uint64) for t in FPT]

def _perm_np(x, T):
    out = T[0][x >> U(56)]
    for j in range(1, 8):
        out |= T[j][(x >> U(56 - 8 * j)) & U(255)]
    return out

def blocks_np(x, sks):
    """x: uint64 array of 64-bit blocks; sks: list of 16 round keys (8 groups each)."""
    x = _perm_np(x, IPN)
    l, r = x >> U(32), x & U(M32)
    for g in sks:
        t = ((r & U(1)) << U(33)) | (r << U(1)) | (r >> U(31))
        f = SPN[0][((t >> U(28)) & U(63)) ^ U(g[0])]
        for i in range(1, 8):
            f ^= SPN[i][((t >> U(28 - 4 * i)) & U(63)) ^ U(g[i])]
        l, r = r, l ^ f
    return _perm_np((r << U(32)) | l, FPN)

def tdes_blocks_np(x, k1, k2, k3, decrypt=False):
    s1, s2, s3 = prepare_keys(k1), prepare_keys(k2), prepare_keys(k3)
    if not decrypt:
        return blocks_np(blocks_np(blocks_np(x, s1), s2[::-1]), s3)
    return blocks_np(blocks_np(blocks_np(x, s3[::-1]), s2), s1[::-1])

def tdes_ecb_np(data, key24, decrypt=False):
    x = np.frombuffer(data, dtype=">u8").astype(np.uint64)
    y = tdes_blocks_np(x, key24[:8], key24[8:16], key24[16:], decrypt)
    return y.astype(">u8").tobytes()

def tdes_ctr_np(data, key24, init_counter=0):
    """CTR mode: keystream = E(counter); encrypt and decrypt are the same operation."""
    nblk = (len(data) + 7) // 8
    ctr = (np.arange(nblk, dtype=np.uint64) + U(init_counter))
    ks = tdes_blocks_np(ctr, key24[:8], key24[8:16], key24[16:]).astype(">u8").tobytes()
    a = np.frombuffer(data, dtype=np.uint8)
    return (a ^ np.frombuffer(ks, dtype=np.uint8)[:len(a)]).tobytes()

def des_ecb_np(data, key8, decrypt=False):
    x = np.frombuffer(data, dtype=">u8").astype(np.uint64)
    sks = prepare_keys(key8)
    return blocks_np(x, sks[::-1] if decrypt else sks).astype(">u8").tobytes()


if __name__ == "__main__":                              # run:  python des_fast.py
    import os, time
    k24 = os.urandom(24)
    data = os.urandom(1024 * 1024)
    t = time.perf_counter(); ct = tdes_ecb_np(data, k24); dt = time.perf_counter() - t
    print(f"3DES-ECB (NumPy) on 1 MB: {dt:.3f} s  ->  {1 / dt:.2f} MB/s")
    print("decrypt gives back the data:", tdes_ecb_np(ct, k24, True) == data)
    key8 = bytes.fromhex("133457799BBCDFF1")
    print("DES FIPS vector (v1):", ecb_v1(bytes.fromhex("0123456789ABCDEF"), key8).hex().upper(), "(expected 85E813540F0AB405)")
