"""Worked examples quoted in the report (toy curve y^2 = x^3 + 2x + 2 over GF(17), G = (5,1), order 19)."""
import json
import ecc_lab as e
from cryptography.hazmat.primitives.asymmetric import ec

T, G = e.TOY, e.TOY.G
out = {}
e.BUGS.clear()
print("== 2G by hand-formula =====================================")
lam = (3 * G[0] ** 2 + T.a) * pow(2 * G[1], -1, 17) % 17
x3 = (lam * lam - 2 * G[0]) % 17; y3 = (lam * (G[0] - x3) - G[1]) % 17
print(f"correct : lambda = (3*5^2+2)/(2*1) = {3*G[0]**2+T.a}/2 = {lam} (mod 17) -> 2G = ({x3},{y3}); on curve: {e.is_on_curve(T,(x3,y3))}")
out["good"] = [lam, x3, y3]
lam2 = (3 * G[0] ** 2) * pow(2 * G[1], -1, 17) % 17
bx = (lam2 * lam2 - 2 * G[0]) % 17; by = (lam2 * (G[0] - bx) - G[1]) % 17
print(f"bug E2  : lambda = (3*5^2)/2 = {3*G[0]**2}/2 = {lam2} (mod 17) -> ({bx},{by}); on curve: {e.is_on_curve(T,(bx,by))}")
out["e2"] = [lam2, bx, by, e.is_on_curve(T, (bx, by))]
print(f"bug E5  : lambda = {3*G[0]**2+T.a} // {2*G[1]} = {(3*G[0]**2+T.a)//(2*G[1])} -> reduced mod 17 = {((3*G[0]**2+T.a)//(2*G[1]))%17} (correct value is {lam})")
out["e5"] = [(3 * G[0] ** 2 + T.a) // (2 * G[1]) % 17, lam]
print("\n== double-and-add trace for 13G ===========================")
k, R, Q, rows = 13, e.INF, G, []
step = 0
while k:
    bit = k & 1
    if bit: R = e.point_add(T, R, Q)
    rows.append([step, bit, "R = R + Q" if bit else "-", str(R), str(Q)])
    print(f"bit {step}: {bit}  {'add ' if bit else 'skip'}  R = {R}   Q(= 2^{step} G) = {Q}")
    Q = e.point_add(T, Q, Q); k >>= 1; step += 1
print("13G =", R, "| table value (16, 4):", R == (16, 4))
out["trace"] = rows
cnt = {"naive_adds": 12, "da_dbl": 4, "da_add": 3}
print("operations: naive repeated addition = 12 additions; double-and-add = 3 useful doublings + 3 additions")
print("\n== ECDH on the toy curve ==================================")
a, b = 3, 7
A, B = e.mul_jacobian(T, a, G), e.mul_jacobian(T, b, G)
sA, sB = e.mul_jacobian(T, a, B), e.mul_jacobian(T, b, A)
print(f"Alice a={a}, A=aG={A};  Bob b={b}, B=bG={B};  shared aB={sA}, bA={sB}, equal={sA==sB}  (= {(a*b)%19}G)")
out["ecdh"] = [a, b, A, B, sA, sB]
print("\n== ECDH on P-256 against OpenSSL ==========================")
da, Qa = e.keygen(e.P256); db, Qb = e.keygen(e.P256)
mine = e.ecdh(e.P256, da, Qb); mine2 = e.ecdh(e.P256, db, Qa)
pa = ec.derive_private_key(da, ec.SECP256R1()); pbk = ec.derive_private_key(db, ec.SECP256R1())
ref = pa.exchange(ec.ECDH(), pbk.public_key())
print("shared x-coordinate (hex, first 16):", hex(mine)[2:18], "| both sides equal:", mine == mine2, "| equals OpenSSL:", mine.to_bytes(32, 'big') == ref)
out["p256_ok"] = mine == mine2 and mine.to_bytes(32, "big") == ref
print("invalid point rejected:", end=" ")
try: e.ecdh(e.P256, da, (1, 2))
except ValueError as ex: print("yes ->", ex)
json.dump(out, open("ecc_demo.json", "w"), indent=1)
