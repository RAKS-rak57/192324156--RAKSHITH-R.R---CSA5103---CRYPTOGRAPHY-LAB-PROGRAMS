#!/usr/bin/env python3
"""Part II Task 6 - secure mailing at scale: SQLite key store, recipient key-state machine, hybrid engine, growth experiment.
Test keys only; recipient private keys are generated at run time (never stored in source)."""
import os, sys, json, time, sqlite3, struct, hashlib, statistics
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

R = os.path.join(os.path.dirname(__file__), "..", "results"); W = os.path.join(os.path.dirname(__file__), "..", "work"); os.makedirs(R, exist_ok=True)
OAEP = lambda: padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
DAY = 86400; NOW = int(time.time()); TRUST_RANK = {"none": 0, "marginal": 1, "full": 2}; MIN_TRUST = "marginal"
SCHEMA = """CREATE TABLE keys(key_id TEXT PRIMARY KEY, addr TEXT, pem TEXT, fingerprint TEXT, not_before INT, not_after INT, revoked_at INT, trust TEXT)"""


def fp_of(pub): return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
def pem_of(pub): return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class KeyStore:
    def __init__(self, path, index=True):
        if os.path.exists(path): os.remove(path)
        self.db = sqlite3.connect(path); self.db.execute(SCHEMA)
        if index: self.db.execute("CREATE INDEX idx_addr ON keys(addr)")
    def add(self, key_id, addr, pub, nb, na, trust="full", revoked_at=None):
        self.db.execute("INSERT INTO keys VALUES (?,?,?,?,?,?,?,?)", (key_id, addr, pem_of(pub), fp_of(pub), nb, na, revoked_at, trust))
    def revoke(self, key_id, when): self.db.execute("UPDATE keys SET revoked_at=? WHERE key_id=?", (when, key_id))
    def commit(self): self.db.commit()
    def rows(self, addr): return self.db.execute("SELECT key_id,pem,fingerprint,not_before,not_after,revoked_at,trust FROM keys WHERE addr=? ORDER BY not_before DESC", (addr,)).fetchall()


def key_state(row, now):
    """Fail-closed state of ONE key record. Order matters: REVOKED overrides everything."""
    key_id, pem, fp, nb, na, rev, trust = row
    if rev is not None and rev <= now: return "REVOKED"
    if now < nb: return "NOT_YET_VALID"
    if now > na: return "EXPIRED"
    if TRUST_RANK[trust] < TRUST_RANK[MIN_TRUST]: return "UNTRUSTED"
    return "ACTIVE"


def select_key(store, addr, now):
    """Returns (row or None, reason). The newest ACTIVE key wins (rollover); otherwise the reason of the newest key explains the skip."""
    rows = store.rows(addr)
    if not rows: return None, "MISSING"
    for r in rows:
        if key_state(r, now) == "ACTIVE": return r, "ACTIVE"
    return None, key_state(rows[0], now)


def prepare(store, recipients, message, now, ops, join=True):
    valid, skipped = [], []
    for a in recipients:
        r, why = select_key(store, a, now); (valid.append((a, r)) if r else skipped.append((a, why)))
    if not valid: return None, valid, skipped
    ks = AESGCM.generate_key(bit_length=256); nonce = os.urandom(12); header = b"MSX1" + struct.pack(">H", len(valid))
    wraps = b"" if not join else []
    for a, r in valid:
        pub = serialization.load_pem_public_key(r[1].encode()); w = pub.encrypt(ks, OAEP()); ops["pk"] += 1; ent = bytes.fromhex(r[2])[:8] + struct.pack(">H", len(w)) + w
        if join: wraps.append(ent)
        else: wraps += ent                                           # naive repeated concatenation: copies the growing buffer every time
    if join: wraps = b"".join(wraps)
    ct = AESGCM(ks).encrypt(nonce, message, header + wraps); ops["sym"] += 1
    return header + wraps + nonce + struct.pack(">I", len(ct)) + ct, valid, skipped


def try_decrypt(blob, priv):
    """A recipient's own decryption attempt using ONLY the public message."""
    n = struct.unpack(">H", blob[4:6])[0]; p = 6; entries = {}
    for _ in range(n):
        kid = blob[p:p + 8]; wl = struct.unpack(">H", blob[p + 8:p + 10])[0]; entries[kid] = blob[p + 10:p + 10 + wl]; p += 10 + wl
    header = blob[:p]; nonce = blob[p:p + 12]; ctl = struct.unpack(">I", blob[p + 12:p + 16])[0]; ct = blob[p + 16:p + 16 + ctl]
    kid = bytes.fromhex(fp_of(priv.public_key()))[:8]
    if kid not in entries: return None, "no wrapped key for this keyid"
    try: ks = priv.decrypt(entries[kid], OAEP())
    except Exception: return None, "unwrap failed"
    return AESGCM(ks).decrypt(nonce, ct, header), "decrypted"


res = {}
print("generating 60 test RSA-2048 keys ..."); pool = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(60)]
store = KeyStore(W + "/keystore.db")
# ---------------------------------------------------------------- 6.3 : list of 10 with every skip reason
spec = [("r01@clinic.test", "ACTIVE"), ("r02@clinic.test", "ACTIVE"), ("r03@clinic.test", "ACTIVE"), ("r04@clinic.test", "EXPIRED"), ("r05@clinic.test", "REVOKED"),
        ("r06@clinic.test", "ACTIVE"), ("r07@clinic.test", "UNTRUSTED"), ("r08@clinic.test", "ROLLOVER"), ("r09@clinic.test", "ACTIVE"), ("r10@clinic.test", "MISSING")]
keys10 = {}
for i, (a, kind) in enumerate(spec):
    k = pool[i]; keys10[a] = k; pub = k.public_key()
    if kind == "ACTIVE": store.add(f"{a}#1", a, pub, NOW - 100 * DAY, NOW + 200 * DAY)
    elif kind == "EXPIRED": store.add(f"{a}#1", a, pub, NOW - 400 * DAY, NOW - 35 * DAY)
    elif kind == "REVOKED": store.add(f"{a}#1", a, pub, NOW - 100 * DAY, NOW + 200 * DAY, revoked_at=NOW - 3 * DAY)
    elif kind == "UNTRUSTED": store.add(f"{a}#1", a, pub, NOW - 100 * DAY, NOW + 200 * DAY, trust="none")
    elif kind == "ROLLOVER":                                          # old key expired last month, new key (pool[40]) issued 20 days ago
        store.add(f"{a}#1", a, pub, NOW - 400 * DAY, NOW - 30 * DAY); keys10[a] = pool[40]; store.add(f"{a}#2", a, pool[40].public_key(), NOW - 20 * DAY, NOW + 345 * DAY)
store.commit()
msg = b"Newsletter: flu clinic opens Monday. " * 100                 # 3,700-byte test message
ops = dict(pk=0, sym=0); t = time.perf_counter(); blob, valid, skipped = prepare(store, [a for a, _ in spec], msg, NOW, ops); dt_ = time.perf_counter() - t
from collections import Counter
res["t63"] = dict(n=len(spec), valid=[a for a, _ in valid], valid_key_ids=[r[0] for _, r in valid], skipped=skipped, reasons=dict(Counter(w for _, w in skipped)), pk_ops=ops["pk"], sym_ops=ops["sym"], size=len(blob), msg_size=len(msg), time_ms=dt_ * 1e3)
res["t63"]["summary_line"] = f"Recipients valid: {len(valid)} | skipped: {len(skipped)} ({', '.join(f'{v} {k.lower()}' for k, v in Counter(w for _, w in skipped).items())})"

# ---------------------------------------------------------------- 6.4 : five recipients, hand-derived expectation vs real decrypt attempts
store5 = KeyStore(W + "/keystore5.db"); k5 = {}
five = [("alice@x.test", "ACTIVE", True, "valid, in date, trusted"), ("bob@x.test", "EXPIRED", False, "notAfter was 35 days ago"), ("carol@x.test", "REVOKED", False, "revoked 3 days ago although still inside its validity period"),
        ("dave@x.test", "ROLLOVER", True, "old key expired, NEW key active - must encrypt to the new key, not the old"), ("erin@x.test", "ACTIVE", True, "valid, marginal trust is >= the minimum")]
for i, (a, kind, exp, why) in enumerate(five):
    k = pool[10 + i]; k5[a] = k; p = k.public_key()
    if kind == "ACTIVE": store5.add(f"{a}#1", a, p, NOW - 50 * DAY, NOW + 100 * DAY, trust=("marginal" if a.startswith("erin") else "full"))
    elif kind == "EXPIRED": store5.add(f"{a}#1", a, p, NOW - 400 * DAY, NOW - 35 * DAY)
    elif kind == "REVOKED": store5.add(f"{a}#1", a, p, NOW - 50 * DAY, NOW + 100 * DAY, revoked_at=NOW - 3 * DAY)
    elif kind == "ROLLOVER":
        old = k; store5.add(f"{a}#1", a, old.public_key(), NOW - 400 * DAY, NOW - 30 * DAY); k5[a] = pool[20]; store5.add(f"{a}#2", a, pool[20].public_key(), NOW - 20 * DAY, NOW + 345 * DAY); k5[a + "_old"] = old
store5.commit(); ops5 = dict(pk=0, sym=0); blob5, v5, s5 = prepare(store5, [a for a, *_ in five], b"CONFIDENTIAL: results", NOW, ops5)
rows = []
for a, kind, exp, why in five:
    out, st = try_decrypt(blob5, k5[a]); rows.append(dict(recipient=a, state=kind, expected="CAN decrypt" if exp else "CANNOT decrypt", why=why, actual="decrypted" if out else f"refused ({st})", match=(out is not None) == exp))
old = k5["dave@x.test_old"]; out, st = try_decrypt(blob5, old); rows.append(dict(recipient="dave@x.test (OLD key)", state="EXPIRED key held by dave", expected="CANNOT decrypt", why="message must not be wrapped for the superseded key", actual="decrypted" if out else f"refused ({st})", match=out is None))
res["t64"] = dict(rows=rows, pk=ops5["pk"], sym=ops5["sym"], valid=[a for a, _ in v5], skipped=s5, size=len(blob5))

# ---------------------------------------------------------------- 6.5 : growth experiment (60 distinct RSA keys reused round-robin as key material; addresses and key_ids are distinct)
msg4k = os.urandom(4000)
def run_growth(index, join=True):
    growth = []
    for n in [1, 10, 100, 1000, 10000]:
        s = KeyStore(W + "/keystore_g.db", index=index)
        for i in range(n): s.add(f"u{i}#1", f"u{i}@bulk.test", pool[i % 60].public_key(), NOW - DAY, NOW + 300 * DAY)
        s.commit(); times = []
        for _ in range(3 if n >= 1000 else 7):
            o = dict(pk=0, sym=0); t = time.perf_counter(); b, v, sk = prepare(s, [f"u{i}@bulk.test" for i in range(n)], msg4k, NOW, o, join); times.append(time.perf_counter() - t)
        t = time.perf_counter()
        for _ in range(200): AESGCM(os.urandom(32)).encrypt(os.urandom(12), msg4k, b"")
        sym_ms = (time.perf_counter() - t) / 200 * 1e3
        growth.append(dict(n=n, pk=o["pk"], sym=o["sym"], size=len(b), time_ms=statistics.median(times) * 1e3, per_recipient_ms=statistics.median(times) * 1e3 / n, naive_sym_ops=n, naive_bytes=n * len(msg4k) + n * 28, sym_ms=sym_ms))
    return growth
res["t65_noindex"] = run_growth(False, False); res["t65_concat"] = run_growth(True, False); growth = run_growth(True, True)
res["t65"] = growth
# larger message: does it change per-recipient cost?
big = os.urandom(1_000_000); s = KeyStore(W + "/keystore_g.db")
for i in range(100): s.add(f"u{i}#1", f"u{i}@bulk.test", pool[i % 60].public_key(), NOW - DAY, NOW + 300 * DAY)
s.commit(); o = dict(pk=0, sym=0); t = time.perf_counter(); b, v, sk = prepare(s, [f"u{i}@bulk.test" for i in range(100)], big, NOW, o)
res["t65_big"] = dict(n=100, msg=len(big), size=len(b), pk=o["pk"], sym=o["sym"], time_ms=(time.perf_counter() - t) * 1e3, naive_bytes=100 * len(big))
# 6.6 extrapolation to 200,000 subscribers from the measured per-recipient cost
per = growth[-1]["per_recipient_ms"]; res["t66"] = dict(subscribers=200000, per_recipient_ms=per, total_s=per * 200000 / 1e3, header_bytes=200000 * (8 + 2 + 256), measured_bytes_per_recipient=(growth[-1]["size"] - growth[0]["size"]) / (growth[-1]["n"] - growth[0]["n"]))
json.dump(res, open(R + "/t6.json", "w"), indent=1, default=str)
print(res["t63"]["summary_line"], res["t63"]["pk_ops"], res["t63"]["sym_ops"], res["t63"]["size"]); print(res["t63"]["skipped"])
for r in rows: print(r["recipient"], r["expected"], r["actual"], r["match"])
for g in res["t65_noindex"]: print("noindex", g["n"], round(g["time_ms"],1), round(g["per_recipient_ms"],3))
for g in res["t65_concat"]: print("index,concat", g["n"], round(g["time_ms"],1), round(g["per_recipient_ms"],3))
for g in growth: print(g["n"], g["pk"], g["sym"], g["size"], round(g["time_ms"],1), round(g["per_recipient_ms"],3))
print(res["t65_big"]); print(res["t66"])
