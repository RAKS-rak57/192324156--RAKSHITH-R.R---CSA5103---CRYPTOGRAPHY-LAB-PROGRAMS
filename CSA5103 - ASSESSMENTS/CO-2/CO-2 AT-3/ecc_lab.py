"""
ecc_lab.py - elliptic-curve arithmetic over a prime field  y^2 = x^3 + a*x + b  (mod p).

Contains the correct code plus switchable seeded bugs E1 ... E7 (active when the name is in BUGS),
and three scalar-multiplication algorithms: naive repeated addition, double-and-add (affine),
double-and-add in Jacobian coordinates and a Montgomery ladder.
"""
from dataclasses import dataclass
import secrets

BUGS = set()
INF = None                                  # the point at infinity (group identity)

@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    G: tuple
    n: int                                  # order of G

TOY = Curve("toy y^2=x^3+2x+2 mod 17", 17, 2, 2, (5, 1), 19)
P256 = Curve("NIST P-256", 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
             0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF - 3,
             0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
             (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
              0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
             0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)
K256 = Curve("secp256k1", 2**256 - 2**32 - 977, 0, 7,
             (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
              0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
             0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

# ------------------------------------------------------------------ affine arithmetic
def is_on_curve(C, P):
    if P is INF:
        return True
    x, y = P
    return (y * y - (x * x * x + C.a * x + C.b)) % C.p == 0

def divmod_p(num, den, p):
    """num / den in the field GF(p)."""
    if "E5" in BUGS:                                    # BUG E5: integer (floor) division, not a modular inverse
        return (num // den) % p
    return num * pow(den, -1, p) % p                    # FIX: multiply by the modular inverse

def neg(C, P):
    return INF if P is INF else (P[0], (-P[1]) % C.p)

def point_add(C, P, Q):
    """P + Q on the curve (affine coordinates)."""
    p = C.p
    if "E1" not in BUGS:                                # BUG E1: identity element not handled (None unpack -> crash)
        if P is INF: return Q
        if Q is INF: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0 and "E4" not in BUGS:   # BUG E4: P + (-P) must give the identity
        return INF
    if P == Q and "E3" not in BUGS:                     # BUG E3: doubling case not separated from the chord case
        a_term = 0 if "E2" in BUGS else C.a             # BUG E2: curve parameter a forgotten in the tangent slope
        lam = divmod_p(3 * x1 * x1 + a_term, 2 * y1, p)
    else:
        lam = divmod_p(y2 - y1, x2 - x1, p)
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

# ------------------------------------------------------------------ scalar multiplication
def mul_naive(C, k, P):
    """k*P by repeated addition: O(k) group operations (only usable for tiny k)."""
    if "E6" in BUGS:                                    # BUG E6: starts at P and loops k times -> (k+1)P, no k mod n
        if k > 100000:
            raise TimeoutError("naive loop would need %d additions" % k)
        R = P
        for _ in range(k):
            R = point_add(C, R, P)
        return R
    k %= C.n
    R = INF
    for _ in range(k):
        R = point_add(C, R, P)
    return R

def mul_double_and_add(C, k, P):
    """Right-to-left double-and-add: O(log k) group operations, affine coordinates."""
    if "E6" in BUGS:
        return mul_naive(C, k, P)
    k %= C.n
    R, Q = INF, P
    while k:
        if k & 1:
            R = point_add(C, R, Q)
        Q = point_add(C, Q, Q)
        k >>= 1
    return R

# ---- Jacobian coordinates: (X, Y, Z) represents the affine point (X/Z^2, Y/Z^3); no inversion per step
def to_jac(P):
    return (0, 1, 0) if P is INF else (P[0], P[1], 1)

def from_jac(C, J):
    X, Y, Z = J
    if Z == 0:
        return INF
    zi = pow(Z, -1, C.p)
    return (X * zi * zi % C.p, Y * zi * zi * zi % C.p)

def jac_double(C, J):
    p = C.p
    X, Y, Z = J
    if Z == 0 or Y == 0:
        return (0, 1, 0)
    YY = Y * Y % p
    S = 4 * X * YY % p
    M = (3 * X * X + C.a * pow(Z, 4, p)) % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * YY * YY) % p
    return (X3, Y3, 2 * Y * Z % p)

def jac_add(C, J1, J2):
    p = C.p
    X1, Y1, Z1 = J1
    X2, Y2, Z2 = J2
    if Z1 == 0: return J2
    if Z2 == 0: return J1
    Z1Z1, Z2Z2 = Z1 * Z1 % p, Z2 * Z2 % p
    U1, U2 = X1 * Z2Z2 % p, X2 * Z1Z1 % p
    S1, S2 = Y1 * Z2 * Z2Z2 % p, Y2 * Z1 * Z1Z1 % p
    if U1 == U2:
        return jac_double(C, J1) if S1 == S2 else (0, 1, 0)
    H, R = (U2 - U1) % p, (S2 - S1) % p
    HH = H * H % p
    HHH = H * HH % p
    V = U1 * HH % p
    X3 = (R * R - HHH - 2 * V) % p
    Y3 = (R * (V - X3) - S1 * HHH) % p
    return (X3, Y3, H * Z1 * Z2 % p)

def mul_jacobian(C, k, P):
    """Double-and-add in Jacobian coordinates: ONE modular inversion in total."""
    k %= C.n
    R, Q = (0, 1, 0), to_jac(P)
    while k:
        if k & 1:
            R = jac_add(C, R, Q)
        Q = jac_double(C, Q)
        k >>= 1
    return from_jac(C, R)

def mul_ladder(C, k, P):
    """Montgomery ladder: same sequence of operations for every key bit (side-channel friendlier)."""
    k %= C.n
    R0, R1 = (0, 1, 0), to_jac(P)
    for i in range(max(k.bit_length(), 1) - 1, -1, -1):
        if (k >> i) & 1:
            R0, R1 = jac_add(C, R0, R1), jac_double(C, R1)
        else:
            R1, R0 = jac_add(C, R0, R1), jac_double(C, R0)
    return from_jac(C, R0)

# ------------------------------------------------------------------ ECDH key exchange
def keygen(C):
    d = secrets.randbelow(C.n - 1) + 1
    return d, mul_jacobian(C, d, C.G)

def ecdh(C, d, Q, mul=None):
    """Shared secret = x-coordinate of d*Q.  The peer's point is validated first (invalid-curve defence)."""
    mul = mul or mul_jacobian
    if "E7" not in BUGS:                                # BUG E7: peer public key never validated
        if Q is INF or not is_on_curve(C, Q):
            raise ValueError("peer public key is not a valid point on the curve")
    S = mul(C, d, Q)
    if S is INF:
        raise ValueError("shared point is the identity")
    return S[0]


if __name__ == "__main__":                              # run:  python ecc_lab.py
    BUGS.clear()
    T = TOY
    print("Toy curve", T.name, " G =", T.G, " order =", T.n)
    print("Multiples of G:", [mul_jacobian(T, k, T.G) for k in range(1, 6)], "...")
    print("19G (should be None = infinity):", mul_jacobian(T, 19, T.G))
    da, Qa = keygen(P256); db, Qb = keygen(P256)
    print("P-256 ECDH, both sides agree:", ecdh(P256, da, Qb) == ecdh(P256, db, Qa))
