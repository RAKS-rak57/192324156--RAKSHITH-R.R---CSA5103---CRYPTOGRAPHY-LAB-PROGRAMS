#!/usr/bin/env python3
"""Part II Task 1 experiments. Generates TEST keys at run time into ../work (never committed to source)."""
import os, sys, json, time, random, subprocess, base64, struct
sys.path.insert(0, os.path.dirname(__file__))
import pgpmail as P
from cryptography.hazmat.primitives import serialization

W = os.path.join(os.path.dirname(__file__), "..", "work"); R = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(W + "/keys", exist_ok=True); os.makedirs(R, exist_ok=True)
CLI = [sys.executable, os.path.join(os.path.dirname(__file__), "pgpmail.py")]
RING = W + "/ring.json"; KEYS = W + "/keys"

# ---------------------------------------------------------------- key ring set-up (web of trust as in Part I Task 5)
names = {"alice": "alice@lab.example", "bob": "bob@clinic.example", "carol": "carol@intro.example", "dave": "dave@intro.example",
         "eve": "eve@intro.example", "frank": "frank@intro.example", "gina": "gina@other.example", "mallory": "mallory@evil.example",
         "erin": "erin@clinic.example"}
if os.path.exists(RING): os.remove(RING)
ring = P.Ring(RING); priv = {}
for n, e in names.items():
    k = P.gen_key(2048); priv[n] = k; open(f"{KEYS}/{n}.pem", "wb").write(P.priv_pem(k)); ring.add(n, e, k.public_key())
os.chmod(KEYS, 0o700)
ring.d["owner_trust"] = {"carol": "full", "dave": "marginal", "eve": "marginal", "frank": "untrusted"}   # Bob's owner-trust table
for s in ["carol", "dave", "eve", "frank"]: ring.certify(s, priv[s], "alice")        # Alice's key: signed by four introducers
for s in ["carol"]: ring.certify(s, priv[s], "bob"); ring.certify(s, priv[s], "erin")
ring.certify("dave", priv["dave"], "gina")                                                # Gina: one marginal signature only
ring.certify("frank", priv["frank"], "mallory")                                           # Mallory: only an untrusted introducer
ring.save()

def run(args):
    t = time.perf_counter(); p = subprocess.run(CLI + args, capture_output=True, text=True); return p.returncode, p.stdout, p.stderr, time.perf_counter() - t

rng = random.Random(4); vocab = "patient report lab result clinic doctor sample blood urine glucose cholesterol follow review dosage hospital branch scan ward nurse".split()
def make_text(n):
    out = []; l = 0
    while l < n:
        w = rng.choice(vocab) + (" " + str(rng.randint(10, 999)) if rng.random() < .3 else ""); out.append(w); l += len(w) + 1
    return (" ".join(out))[:n].encode()

res = {}
# ---------------------------------------------------------------- 1.1 / 1.2 : a normal run with instrumentation + labelled hex view
open(W + "/m_small.txt", "wb").write(b"MEET AT 9")
c, o, e, _ = run(["protect", "--ring", RING, "--keys", KEYS, "--sender", "alice", "--to", "bob", "--infile", W + "/m_small.txt", "--out", W + "/small.asc"])
res["normal_protect"] = dict(code=c, out=o, err=e)
c, o, e, _ = run(["unprotect", "--ring", RING, "--keys", KEYS, "--me", "bob", "--infile", W + "/small.asc"])
res["normal_unprotect"] = dict(code=c, out=o, err=e)
blob = base64.b64decode(open(W + "/small.asc").read().replace("-----BEGIN PGPX MESSAGE-----", "").replace("-----END PGPX MESSAGE-----", ""))
nrec = struct.unpack(">H", blob[5:7])[0]; p = 23 + 10 + 256
labels = [("magic 'PGPX'", 0, 4), ("version", 4, 5), ("recipient count", 5, 7), ("session-key id", 7, 15), ("sender keyid", 15, 23),
          ("recipient keyid", 23, 31), ("wrapped-key length", 31, 33), ("RSA-OAEP wrapped Ks (first 16 B shown)", 33, 49), ("... wrapped Ks continues ...", 49, p),
          ("GCM nonce", p, p + 12), ("ciphertext length", p + 12, p + 16), ("AES-GCM ciphertext+tag", p + 16, len(blob))]
res["hexview"] = [dict(label=l, start=a, end=b, hex=(blob[a:min(b, a + 16)].hex(" ")), length=b - a) for l, a, b in labels]
res["small_blob_len"] = len(blob); res["small_armor_head"] = open(W + "/small.asc").read().splitlines()[:4]

# ---------------------------------------------------------------- 1.3 requirement change : predictions then measurements
msg4k = make_text(4000); msg40k = make_text(40000)
per_rec = 8 + 2 + 256
pred = {"a": dict(case="one recipient, 4 KB", pk_sender=2, sym=1, size_note="header 23 + 266 + nonce/len 16 + GCM(compress(2+256+4000)) ; ~ 1 recipient entry"),
        "b": dict(case="five recipients, 4 KB", pk_sender=6, sym=1, size_note="a + 4 x 266 B = a + 1064 B"),
        "c": dict(case="one recipient, 40 KB (10x)", pk_sender=2, sym=1, size_note="ciphertext grows ~10x (compression ratio permitting), header unchanged")}
cases = {"a": (msg4k, ["bob"]), "b": (msg4k, ["bob", "carol", "dave", "erin", "gina"]), "c": (msg40k, ["bob"])}
meas = {}
for k, (m, to) in cases.items():
    ops = P.Ops(); times = []
    for _ in range(15):
        ops = P.Ops(); t = time.perf_counter(); text, info = P.protect(m, "alice", priv["alice"], ring, to, int(time.time()), ops); times.append(time.perf_counter() - t)
    meas[k] = dict(recipients=len(to), msg=len(m), pk=ops.pk, sym=ops.sym, counts=dict(ops.c), sizes=info["sizes"], time_ms=sorted(times)[len(times) // 2] * 1e3)
    # receiver
    ro = P.Ops(); t = time.perf_counter(); out, st, sg = P.unprotect(text, to[0], priv[to[0]], ring, int(time.time()), ro); meas[k]["recv"] = dict(pk=ro.pk, sym=ro.sym, counts=dict(ro.c), ok=(out == m), trust=st, time_ms=(time.perf_counter() - t) * 1e3)
res["pred"] = pred; res["meas"] = meas

# ---------------------------------------------------------------- 1.4 boundary / tamper tests through the CLI
tests = []
def tcase(name, why, setup_args, tamper=None, me="bob", msgfile=None):
    asc = W + f"/t_{name}.asc"; mf = msgfile
    c1, o1, e1, _ = run(["protect", "--ring", RING, "--keys", KEYS, "--sender", setup_args.get("sender", "alice"), "--to", setup_args.get("to", "bob"), "--infile", mf, "--out", asc])
    if tamper:
        txt = open(asc).read(); open(asc, "w").write(tamper(txt))
    c2, o2, e2, _ = run(["unprotect", "--ring", RING, "--keys", KEYS, "--me", me, "--infile", asc])
    tests.append(dict(name=name, why=why, protect_code=c1, code=c2, out=o2.strip().splitlines()[-1] if o2.strip() else "", err=e2.strip()))

def flip(txt, offset_from_end=None, from_start=None):
    head, rest = "-----BEGIN PGPX MESSAGE-----\n", txt.split("\n", 1)[1].rsplit("-----END", 1)[0]
    raw = bytearray(base64.b64decode(rest))
    if from_start is not None: raw[from_start] ^= 0x01
    else: raw[-offset_from_end] ^= 0x01
    return head + base64.encodebytes(bytes(raw)).decode() + "-----END PGPX MESSAGE-----\n"
open(W + "/m_empty.txt", "wb").write(b""); open(W + "/m_real.txt", "wb").write(make_text(2000))
tcase("empty_message", "zero-length input: tests slicing/length fields and compression of an empty body", {}, msgfile=W + "/m_empty.txt")
tcase("bitflip_ciphertext", "one-bit change in the last ciphertext byte: the AEAD tag must reject it", {}, tamper=lambda t: flip(t, 20), msgfile=W + "/m_real.txt")
tcase("bitflip_wrapped_key", "one bit flipped inside the RSA-OAEP wrapped session key", {}, tamper=lambda t: flip(t, from_start=100), msgfile=W + "/m_real.txt")
tcase("non_recipient", "Frank is not in the recipient list but holds a valid key: must be refused before any decryption", {"to": "bob"}, me="frank", msgfile=W + "/m_real.txt")
tcase("unvalidated_sender", "Gina's key is signed by one marginal introducer only: signature valid but identity not validated", {"sender": "gina"}, msgfile=W + "/m_real.txt")
tcase("untrusted_introducer", "Mallory's key is signed only by an untrusted introducer", {"sender": "mallory"}, msgfile=W + "/m_real.txt")
tcase("truncated", "message cut in half in transit", {}, tamper=lambda t: t[:len(t) // 2] + "\n-----END PGPX MESSAGE-----\n", msgfile=W + "/m_real.txt")
res["boundary"] = tests
# PGP validity evaluation of Alice's key as in Task 5
log = []; st = ring.validity("alice", int(time.time()), None, log); res["alice_validity"] = dict(status=st[0], full=st[1], marg=st[2], log=log)
log = []; st = ring.validity("gina", int(time.time()), None, log); res["gina_validity"] = dict(status=st[0], full=st[1], marg=st[2], log=log)
json.dump(res, open(R + "/t1.json", "w"), indent=1)
print(json.dumps({k: (v if k in ("meas",) else "...") for k, v in res.items()}, indent=1)[:3000])
for t in tests: print(t["name"], t["protect_code"], t["code"], t["out"][:80], "|", t["err"][:100])
print(res["alice_validity"])
