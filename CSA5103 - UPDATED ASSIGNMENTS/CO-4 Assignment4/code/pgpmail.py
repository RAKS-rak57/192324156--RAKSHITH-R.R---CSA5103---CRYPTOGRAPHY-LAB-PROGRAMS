#!/usr/bin/env python3
"""pgpmail.py - PGP-style secure mail engine (CO4 Part II, Task 1).

Message format, ordering of operations and verification logic are the student's own design
(Part I Task 2).  Primitives come from the vetted `cryptography` library
(RSA-PSS, RSA-OAEP, AES-256-GCM, SHA-256, zlib).  All keys are TEST keys generated at run time
and stored outside the source tree; private keys are never printed or logged.

Design (sender):  digest=HASH(M) ; sig=SIGN(KRa,digest) ; P=COMPRESS(len|sig|M) ;
                  Ks=RANDOM ; C=AES-GCM(Ks,P,aad=header) ; for each valid recipient: W=OAEP(KUb,Ks) ;
                  radix-64 armor.
Exit codes: 0 ok | 2 armor/format | 3 not a recipient | 4 unwrap failed | 5 authentication/tamper
            6 decompress | 7 unknown sender | 8 signature invalid | 9 sender key revoked/expired
            20 signature valid but sender key NOT validated by web of trust (warning)
"""
import os, sys, json, zlib, struct, base64, hashlib, time, argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC = b"PGPX"; VERSION = 1
PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP = lambda: padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class Ops:
    """Operation counters used for the experiments."""
    def __init__(self): self.c = dict(pk_sign=0, pk_verify=0, pk_wrap=0, pk_unwrap=0, sym_enc=0, sym_dec=0, hash=0)
    def inc(self, k, n=1): self.c[k] += n
    @property
    def pk(self): return sum(self.c[k] for k in ("pk_sign", "pk_verify", "pk_wrap", "pk_unwrap"))
    @property
    def sym(self): return self.c["sym_enc"] + self.c["sym_dec"]


class PgpError(Exception):
    def __init__(self, code, msg): super().__init__(msg); self.code = code


def fingerprint(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def keyid(pub): return bytes.fromhex(fingerprint(pub))[:8]


def gen_key(bits=2048): return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def pub_pem(pub): return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def priv_pem(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


# ------------------------------------------------------------------ key ring / web of trust
class Ring:
    """Public key ring: users, owner trust (given by the ring owner), certifications (key signatures)."""
    def __init__(self, path): self.path = path; self.d = json.load(open(path)) if os.path.exists(path) else dict(users={}, owner_trust={}, sigs=[])
    def save(self): json.dump(self.d, open(self.path, "w"), indent=1)
    def add(self, name, email, pub, not_after=None, revoked=False):
        self.d["users"][name] = dict(email=email, pem=pub_pem(pub), fp=fingerprint(pub), not_after=not_after, revoked=revoked)
    def pub(self, name): return serialization.load_pem_public_key(self.d["users"][name]["pem"].encode())
    def certify(self, signer_name, signer_priv, target):
        u = self.d["users"][target]; msg = (u["fp"] + "|" + u["email"]).encode()
        sig = signer_priv.sign(msg, PSS(), hashes.SHA256())
        self.d["sigs"].append(dict(signer=signer_name, target=target, sig=base64.b64encode(sig).decode()))
    def by_keyid(self, kid):
        for n, u in self.d["users"].items():
            if bytes.fromhex(u["fp"])[:8] == kid: return n
        return None
    def key_usable(self, name, now):
        u = self.d["users"].get(name)
        if u is None: return False, "missing"
        if u["revoked"]: return False, "revoked"
        if u["not_after"] is not None and now > u["not_after"]: return False, "expired"
        return True, "ok"
    def validity(self, target, now, ops=None, log=None):
        """Web-of-trust rule: VALID if >=1 FULL introducer or >=2 MARGINAL introducers (Part I Task 5.1)."""
        u = self.d["users"][target]; msg = (u["fp"] + "|" + u["email"]).encode(); full = marg = bad = 0
        for s in self.d["sigs"]:
            if s["target"] != target: continue
            ok, why = self.key_usable(s["signer"], now)
            if not ok:
                if log is not None: log.append(f"signer {s['signer']} ignored ({why})")
                continue
            try:
                self.pub(s["signer"]).verify(base64.b64decode(s["sig"]), msg, PSS(), hashes.SHA256())
                if ops: ops.inc("pk_verify")
            except InvalidSignature:
                bad += 1
                if log is not None: log.append(f"signature of {s['signer']} on {target} INVALID")
                continue
            t = self.d["owner_trust"].get(s["signer"], "unknown")
            if log is not None: log.append(f"signature of {s['signer']} on {target} valid, owner-trust={t}")
            if t == "full": full += 1
            elif t == "marginal": marg += 1
        if full >= 1 or marg >= 2: status = "VALID"
        elif bad > 0 and full + marg == 0: status = "INVALID"      # only forged certifications present
        else: status = "UNKNOWN"                                  # not enough trusted evidence
        return status, full, marg


# ------------------------------------------------------------------ sender
def protect(message, sender_name, sender_priv, ring, recipients, now, ops, verbose=None, ring_trust_check=True):
    """Returns (armored_text, info).  Raises PgpError for sender-side failures."""
    say = verbose or (lambda s: None)
    if not recipients: raise PgpError(3, "no recipient given")
    ks_ok = ring.key_usable(sender_name, now)
    if not ks_ok[0]: raise PgpError(9, f"sender key {ks_ok[1]}")
    valid, skipped = [], []
    for r in recipients:
        ok, why = ring.key_usable(r, now)
        (valid if ok else skipped).append(r if ok else (r, why))
    if not valid: raise PgpError(3, "no usable recipient key: " + str(skipped))
    digest = hashlib.sha256(message).digest(); ops.inc("hash")
    sig = sender_priv.sign(message, PSS(), hashes.SHA256()); ops.inc("pk_sign"); ops.inc("hash")
    payload = struct.pack(">H", len(sig)) + sig + message
    comp = zlib.compress(payload, 9)
    ks = AESGCM.generate_key(bit_length=256); ks_id = hashlib.sha256(ks).digest()[:8]
    say(f"[1] digest SHA-256(M)            : {digest.hex()[:32]}...  ({len(message)} B message)")
    say(f"[2] signature RSA-PSS with KR({sender_name}) : {len(sig)} B  (key used: {sender_name} PRIVATE)")
    say(f"[3] compress(sig|M)              : {len(payload)} B -> {len(comp)} B")
    say(f"[4] session key id (not the key)  : {ks_id.hex()}")
    sender_kid = keyid(ring.pub(sender_name))
    wraps = []
    for r in valid:
        w = ring.pub(r).encrypt(ks, OAEP()); ops.inc("pk_wrap")
        wraps.append((keyid(ring.pub(r)), w))
        say(f"[5] wrap Ks for {r:<8} RSA-OAEP with KU({r}) : {len(w)} B, keyid {wraps[-1][0].hex()}")
    header = MAGIC + bytes([VERSION]) + struct.pack(">H", len(wraps)) + ks_id + sender_kid
    for kid, w in wraps: header += kid + struct.pack(">H", len(w)) + w
    nonce = os.urandom(12)
    ct = AESGCM(ks).encrypt(nonce, comp, header); ops.inc("sym_enc")
    blob = header + nonce + struct.pack(">I", len(ct)) + ct
    say(f"[6] AES-256-GCM(Ks, compressed, aad=header) : {len(comp)} B -> {len(ct)} B (16 B tag)")
    armor = base64.encodebytes(blob).decode()
    text = "-----BEGIN PGPX MESSAGE-----\n" + armor + "-----END PGPX MESSAGE-----\n"
    info = dict(session_key_id=ks_id.hex(), sizes=dict(message=len(message), payload=len(payload), compressed=len(comp), signature=len(sig),
                header=len(header), ciphertext=len(ct), binary=len(blob), armored=len(text)), valid=valid, skipped=skipped, parts=dict(
                magic=4, version=1, nrec=2, ks_id=8, sender_kid=8, per_recipient=8 + 2 + len(wraps[0][1]), nonce=12, ctlen=4, ct=len(ct)))
    return text, info


# ------------------------------------------------------------------ receiver
def unprotect(text, me_name, me_priv, ring, now, ops, verbose=None):
    """Returns (message, status_string, signer_name).  Raises PgpError(code, msg) on every failed check (fail closed)."""
    say = verbose or (lambda s: None)
    try:
        body = text.replace("-----BEGIN PGPX MESSAGE-----", "").replace("-----END PGPX MESSAGE-----", "")
        blob = base64.b64decode(body); say(f"[1] radix-64 decoded: {len(blob)} B")
        if blob[:4] != MAGIC or blob[4] != VERSION: raise ValueError("bad magic/version")
        nrec = struct.unpack(">H", blob[5:7])[0]; ks_id = blob[7:15]; sender_kid = blob[15:23]; p = 23; wraps = {}
        for _ in range(nrec):
            kid = blob[p:p + 8]; wl = struct.unpack(">H", blob[p + 8:p + 10])[0]; wraps[kid] = blob[p + 10:p + 10 + wl]; p += 10 + wl
        header = blob[:p]; nonce = blob[p:p + 12]; ctl = struct.unpack(">I", blob[p + 12:p + 16])[0]; ct = blob[p + 16:p + 16 + ctl]
        if len(ct) != ctl: raise ValueError("truncated ciphertext")
    except Exception as e:
        raise PgpError(2, f"malformed message ({e})")
    say(f"[2] parsed header: {nrec} recipient(s), session-key id {ks_id.hex()}, sender keyid {sender_kid.hex()}")
    my_kid = keyid(me_priv.public_key())
    if my_kid not in wraps: raise PgpError(3, f"{me_name} is not in the recipient list (keyid {my_kid.hex()})")
    try:
        ks = me_priv.decrypt(wraps[my_kid], OAEP()); ops.inc("pk_unwrap")
    except Exception: raise PgpError(4, "session-key unwrap failed")
    if hashlib.sha256(ks).digest()[:8] != ks_id: raise PgpError(4, "session-key id mismatch")
    say(f"[3] Ks recovered with KR({me_name}) (RSA-OAEP), id check OK")
    try:
        comp = AESGCM(ks).decrypt(nonce, ct, header); ops.inc("sym_dec")
    except InvalidTag: raise PgpError(5, "authentication tag mismatch: ciphertext or header modified")
    say(f"[4] AES-GCM tag verified, decrypted {len(ct)} B -> {len(comp)} B")
    try: payload = zlib.decompress(comp)
    except zlib.error: raise PgpError(6, "decompression failed")
    sl = struct.unpack(">H", payload[:2])[0]; sig = payload[2:2 + sl]; msg = payload[2 + sl:]
    say(f"[5] decompressed {len(comp)} B -> {len(payload)} B ; signature {sl} B ; message {len(msg)} B")
    signer = ring.by_keyid(sender_kid)
    if signer is None: raise PgpError(7, f"unknown sender key {sender_kid.hex()}")
    ok, why = ring.key_usable(signer, now)
    if not ok: raise PgpError(9, f"sender key {signer} is {why}")
    try:
        ring.pub(signer).verify(sig, msg, PSS(), hashes.SHA256()); ops.inc("pk_verify"); ops.inc("hash")
    except InvalidSignature: raise PgpError(8, "signature invalid: message not signed by claimed key")
    say(f"[6] signature verified with KU({signer})  -> cryptographically VALID")
    log = []; status, full, marg = ring.validity(signer, now, ops, log)
    for l in log: say("    web-of-trust: " + l)
    say(f"[7] key validity of {signer}: {status} (full={full}, marginal={marg})")
    return msg, ("TRUSTED" if status == "VALID" else "UNVALIDATED"), signer


# ------------------------------------------------------------------ CLI
def main(argv=None):
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd")
    a = sp.add_parser("protect"); a.add_argument("--ring"); a.add_argument("--keys"); a.add_argument("--sender"); a.add_argument("--to"); a.add_argument("--infile"); a.add_argument("--out")
    b = sp.add_parser("unprotect"); b.add_argument("--ring"); b.add_argument("--keys"); b.add_argument("--me"); b.add_argument("--infile")
    args = ap.parse_args(argv); now = int(time.time()); ops = Ops(); v = lambda s: print(s)
    ring = Ring(args.ring)
    load = lambda n: serialization.load_pem_private_key(open(os.path.join(args.keys, n + ".pem"), "rb").read(), None)
    try:
        if args.cmd == "protect":
            msg = open(args.infile, "rb").read()
            text, info = protect(msg, args.sender, load(args.sender), ring, args.to.split(","), now, ops, v)
            open(args.out, "w").write(text)
            print(f"OK session-key-id={info['session_key_id']} recipients={len(info['valid'])} skipped={info['skipped']} pk_ops={ops.pk} sym_ops={ops.sym} sizes={info['sizes']}")
            return 0
        if args.cmd == "unprotect":
            msg, st, signer = unprotect(open(args.infile).read(), args.me, load(args.me), ring, now, ops, v)
            print(f"OK signer={signer} trust={st} message={msg[:60]!r}")
            if st == "UNVALIDATED":
                print("WARNING: signature is mathematically valid but the signer's key is NOT validated by your web of trust", file=sys.stderr); return 20
            return 0
    except PgpError as e:
        print(f"ERROR[{e.code}]: {e}", file=sys.stderr); return e.code


if __name__ == "__main__": sys.exit(main())
