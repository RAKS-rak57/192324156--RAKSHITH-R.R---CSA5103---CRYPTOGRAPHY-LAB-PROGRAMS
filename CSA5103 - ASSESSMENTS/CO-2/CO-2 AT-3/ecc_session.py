"""Reproduces the ECC debugging session: seeded bugs E1..E7 are fixed one at a time and the tests re-run."""
import json
import ecc_lab as e
from cryptography.hazmat.primitives.asymmetric import ec

TOY, P256, K256 = e.TOY, e.P256, e.K256
G = TOY.G
KNOWN = [(5,1),(6,3),(10,6),(3,1),(9,16),(16,13),(0,6),(13,7),(7,6),(7,11),(13,10),(0,11),(16,4),(9,1),(3,16),(10,11),(6,14),(5,16)]
D = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
D2 = 0x0FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA098765432

def safe(f):
    def run():
        try: return bool(f())
        except Exception: return False
    return run

@safe
def u1(): return e.point_add(TOY, G, e.INF) == G and e.point_add(TOY, e.INF, G) == G
@safe
def u2(): return e.point_add(TOY, G, e.neg(TOY, G)) is e.INF
@safe
def u3(): return e.point_add(TOY, G, G) == (6, 3)
@safe
def u4(): return e.point_add(TOY, (6, 3), G) == (10, 6)
@safe
def u5(): return all(e.mul_double_and_add(TOY, k, G) == KNOWN[k - 1] for k in range(1, 19)) and e.mul_double_and_add(TOY, 19, G) is e.INF
def _ref_pub(curve, d):
    n = ec.derive_private_key(d, curve).public_key().public_numbers(); return (n.x, n.y)
@safe
def u6(): return e.mul_double_and_add(K256, D, K256.G) == _ref_pub(ec.SECP256K1(), D)
@safe
def u7(): return e.mul_double_and_add(P256, D, P256.G) == _ref_pub(ec.SECP256R1(), D)
@safe
def u8():
    pa, pb = _ref_pub(ec.SECP256R1(), D), _ref_pub(ec.SECP256R1(), D2)
    ref = ec.derive_private_key(D, ec.SECP256R1()).exchange(ec.ECDH(), ec.derive_private_key(D2, ec.SECP256R1()).public_key())
    mine = e.ecdh(P256, D, pb, e.mul_double_and_add)
    return mine.to_bytes(32, "big") == ref and mine == e.ecdh(P256, D2, pa, e.mul_double_and_add)
@safe
def u9():
    try: e.ecdh(P256, D, (1, 2), e.mul_double_and_add); return False      # (1,2) is not on P-256
    except ValueError: return True

TESTS = [("U1 P + O = P", u1), ("U2 P + (-P) = O", u2), ("U3 2G = (6,3) on toy curve", u3), ("U4 2G + G = 3G", u4),
         ("U5 kG table k=1..19 (toy)", u5), ("U6 secp256k1 (a=0) = OpenSSL", u6), ("U7 P-256 (a=-3) = OpenSSL", u7),
         ("U8 ECDH P-256 = OpenSSL", u8), ("U9 invalid point rejected", u9)]
ORDER = [("start (7 bugs)", None), ("fix E1 identity", "E1"), ("fix E4 P+(-P)", "E4"), ("fix E3 doubling case", "E3"),
         ("fix E5 modular division", "E5"), ("fix E6 scalar mult", "E6"), ("fix E2 curve parameter a", "E2"), ("fix E7 point validation", "E7")]
if __name__ == "__main__":
    e.BUGS.clear(); e.BUGS.update({f"E{i}" for i in range(1, 8)})
    rows = []
    for name, fix in ORDER:
        if fix: e.BUGS.discard(fix)
        res = [t() for _, t in TESTS]
        rows.append({"step": name, "tests": res, "passed": sum(res)})
        print(f"{name:26s} {''.join('P' if r else '.' for r in res)}  {sum(res)}/{len(res)}")
    e.BUGS.clear()
    # the "certain curve parameters" symptom: only E2 present
    e.BUGS.add("E2")
    sym = {"secp256k1 (a = 0)": u6(), "P-256 (a = -3)": u7(), "toy curve (a = 2)": u3()}
    print("only E2 active:", sym)
    e.BUGS.clear()
    json.dump({"rows": rows, "tests": [t for t, _ in TESTS], "only_e2": sym}, open("ecc_session.json", "w"), indent=1)
