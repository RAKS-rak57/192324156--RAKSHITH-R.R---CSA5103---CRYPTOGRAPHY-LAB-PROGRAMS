#!/usr/bin/env python3
"""Part II Task 2 - S/MIME (OpenSSL CMS) vs PGP-style tool.  Requires run_t1.py and pki.py to have been run."""
import os, sys, json, subprocess, time, random, datetime as dt
sys.path.insert(0, os.path.dirname(__file__))
import pki, pgpmail as P
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

W = os.path.join(os.path.dirname(__file__), "..", "work"); R = os.path.join(os.path.dirname(__file__), "..", "results"); D = W + "/pki"
os.makedirs(R, exist_ok=True)
pki.build()                                                      # fresh test hierarchy each run
def sh(cmd, inp=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=D); return p.returncode, p.stdout, p.stderr
LD = lambda n: x509.load_pem_x509_certificate(open(f"{D}/{n}.pem", "rb").read())


# ------------------------------------------------------------ own certificate-path validator (the repaired Part I Task 4 logic)
class Counter: n = 0
def validate_signer(leaf, pool, roots, from_email, crls, now, log):
    """Returns (decision, reason). Every check appends one line to log."""
    def sigok(cert, issuer):
        Counter.n += 1
        try: issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm); return True
        except Exception: return False
    chain = [leaf]; cur = leaf
    while True:                                                    # path construction
        if any(cur.subject == r.subject and cur.public_bytes(serialization.Encoding.DER) == r.public_bytes(serialization.Encoding.DER) for r in roots): break
        nxt = next((c for c in pool + roots if c.subject == cur.issuer and c is not cur), None)
        if nxt is None:
            log.append(f"S1 path building: issuer '{cur.issuer.rfc4514_string()}' of '{cur.subject.rfc4514_string()}' not found"); return "REJECT", "unable to build path (missing issuer)"
        chain.append(nxt); cur = nxt
        if len(chain) > 6: return "REJECT", "path too long"
    log.append("S1 path built: " + " -> ".join(c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value for c in chain))
    top = chain[-1]
    if not any(top.public_bytes(serialization.Encoding.DER) == r.public_bytes(serialization.Encoding.DER) for r in roots):
        log.append("S2 trust anchor: top of chain is NOT in TrustedRoots"); return "REJECT", "chain does not end at a trusted root"
    log.append("S2 trust anchor: top of chain is a trusted root")
    for i, c in enumerate(chain[:-1]):                              # signatures along the path
        if not sigok(c, chain[i + 1]): log.append(f"S3 signature of '{c.subject.rfc4514_string()}' by its issuer FAILS"); return "REJECT", "bad certificate signature"
    log.append(f"S3 {len(chain) - 1} certificate signature(s) verified")
    for c in chain:
        if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
            log.append(f"S4 validity: '{c.subject.rfc4514_string()}' expired/not yet valid (notAfter {c.not_valid_after_utc:%Y-%m-%d})"); return "REJECT", "certificate expired or not yet valid"
    log.append("S4 validity period OK for every certificate")
    for i, c in enumerate(chain[1:], 1):                           # CA constraints
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca: log.append("S5 basicConstraints: issuer is not a CA"); return "REJECT", "issuer not a CA"
        if bc.path_length is not None and i - 1 > bc.path_length: log.append("S5 pathLen exceeded"); return "REJECT", "path length exceeded"
    log.append("S5 CA flags / pathLenConstraint OK")
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value; eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if not ku.digital_signature or ExtendedKeyUsageOID.EMAIL_PROTECTION not in eku: log.append("S6 leaf key usage / EKU does not allow S/MIME signing"); return "REJECT", "key usage"
    log.append("S6 leaf KeyUsage=digitalSignature and EKU=emailProtection")
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name)
    if from_email.lower() not in [s.lower() for s in sans]:
        log.append(f"S7 identity: From '{from_email}' not in certificate SAN {sans}"); return "REJECT", "sender address does not match certificate"
    log.append(f"S7 identity: From '{from_email}' equals certificate SAN")
    for c, iss in zip(chain[:-1], chain[1:]):                       # revocation
        for crl in crls:
            if crl.issuer == iss.subject:
                Counter.n += 1
                if not crl.is_signature_valid(iss.public_key()): log.append("S8 CRL signature invalid"); return "REJECT", "bad CRL"
                if crl.get_revoked_certificate_by_serial_number(c.serial_number) is not None:
                    log.append(f"S8 revocation: serial {c.serial_number:x} is on the CRL of '{iss.subject.rfc4514_string()}'"); return "REJECT", "certificate revoked"
    log.append("S8 revocation: not listed on the CRL")
    return "ACCEPT", "all checks passed"


res = {}
now = dt.datetime.now(dt.timezone.utc)
root, inter = LD("root"), LD("inter"); crl = x509.load_pem_x509_crl(open(f"{D}/inter.crl.pem", "rb").read())
open(D + "/trust_crl.pem", "wb").write(open(D + "/root.pem", "rb").read() + open(D + "/inter.crl.pem", "rb").read())
open(D + "/msg4k.txt", "wb").write(open(W + "/m_real.txt", "rb").read() * 2)          # 4000-byte test message (same text as Task 1)
msg4k = open(D + "/msg4k.txt", "rb").read()

# ------------------------------------------------------------ 2.1 normal case - Solution A: S/MIME
VERIFY = "openssl cms -verify -CAfile trust_crl.pem -crl_check -verify_email {em}"
steps = {}
rc, o, e = sh("openssl cms -sign -in msg4k.txt -signer user1.pem -inkey user1.key -certfile inter.pem -out a_signed.msg"); steps["sign"] = (rc, e)
rc, o, e = sh("openssl cms -encrypt -in a_signed.msg -recip user2.pem -aes-256-cbc -out a_enc.msg"); steps["encrypt"] = (rc, e)
rc, o, e = sh("openssl cms -decrypt -in a_enc.msg -recip user2.pem -inkey user2.key -out a_dec.msg"); steps["decrypt"] = (rc, e)
rc, o, e = sh(VERIFY.format(em="user1@hospital.test") + " -in a_dec.msg -signer a_signer.pem -out a_plain.txt"); steps["verify"] = (rc, e)
same = open(D + "/a_plain.txt", "rb").read().strip() == msg4k.strip()
log = []; Counter.n = 0
leaf1 = x509.load_pem_x509_certificate(open(D + "/a_signer.pem", "rb").read())
dec, why = validate_signer(leaf1, [inter], [root], "user1@hospital.test", [crl], now, log)
res["smime_normal"] = dict(steps={k: dict(rc=v[0], err=v[1].strip()) for k, v in steps.items()}, plaintext_ok=same, validator=dict(decision=dec, reason=why, log=log, pk_verifies=Counter.n),
                           signer_subject=leaf1.subject.rfc4514_string(), signer_issuer=leaf1.issuer.rfc4514_string())
rc, o, e = sh("openssl cms -cmsout -print -in a_enc.msg | head -30"); res["smime_enc_structure"] = o
rc, o, e = sh("openssl verify -show_chain -crl_check -CAfile trust_crl.pem -untrusted inter.pem a_signer.pem"); res["openssl_verify_chain"] = o + e
sizes = {}
for f in ["a_signed.msg", "a_enc.msg"]: sizes[f] = os.path.getsize(f"{D}/{f}")
rc, o, e = sh("openssl cms -sign -nocerts -in msg4k.txt -signer user1.pem -inkey user1.key -out a_signed_nocerts.msg"); sizes["signed_nocerts"] = os.path.getsize(D + "/a_signed_nocerts.msg")
rc, o, e = sh("openssl cms -sign -in msg4k.txt -signer user1.pem -inkey user1.key -certfile inter.pem -nodetach -binary -outform DER -out a_signed.der && openssl cms -encrypt -binary -in a_signed.der -recip user2.pem -aes-256-cbc -outform DER -out a_enc.der")
sizes["enc_der"] = os.path.getsize(D + "/a_enc.der")
rc, o, e = sh("openssl cms -sign -in msg4k.txt -signer user1.pem -inkey user1.key -certfile inter.pem -nodetach -binary -outform DER -out a_signed_z.der -stream 2>&1; openssl cms -compress -in msg4k.txt -outform DER -out a_z.der 2>&1; ls a_z.der >/dev/null 2>&1 && echo ok")
sizes["leaf_der"] = len(leaf1.public_bytes(serialization.Encoding.DER)); sizes["inter_der"] = len(inter.public_bytes(serialization.Encoding.DER)); res["smime_sizes"] = sizes

# ------------------------------------------------------------ 2.1 normal case - Solution B: PGP-style tool (User1=alice, User2=bob)
ring = P.Ring(W + "/ring.json"); keys = {n: serialization.load_pem_private_key(open(f"{W}/keys/{n}.pem", "rb").read(), None) for n in ["alice", "bob", "gina"]}
ops_s = P.Ops(); tnow = int(time.time()); text, info = P.protect(msg4k, "alice", keys["alice"], ring, ["bob"], tnow, ops_s)
ops_r = P.Ops(); lines = []; out, st, sg = P.unprotect(text, "bob", keys["bob"], ring, tnow, ops_r, lines.append)
pgp_key_overhead = len(ring.d["users"]["alice"]["pem"]) and len(keys["alice"].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
n_cert_sigs = len([s for s in ring.d["sigs"] if s["target"] == "alice"])
res["pgp_normal"] = dict(ok=(out == msg4k), trust=st, signer=sg, lines=lines, sender_ops=dict(ops_s.c), recv_ops=dict(ops_r.c), sizes=info["sizes"],
                         key_overhead=dict(public_key_der=pgp_key_overhead, certification_sigs=n_cert_sigs, certification_bytes=n_cert_sigs * 256))
# ------------------------------------------------------------ 2.2 S/MIME failure cases
def sign(signer, certfile=True, out="f.msg", body=None):
    if body is not None: open(D + "/fbody.txt", "wb").write(body)
    cf = "-certfile inter.pem" if certfile is True else (f"-certfile {certfile}" if certfile else "")
    return sh(f"openssl cms -sign -in {'fbody.txt' if body is not None else 'msg4k.txt'} -signer {signer}.pem -inkey {signer}.key {cf} -out {out}")
cases = []
def case(cid, title, predict, keyword, signer, em, certfile=True, verify_extra="", tamper=None, validator_args=None):
    sign(signer, certfile)
    if tamper: txt = open(D + "/f.msg").read().replace(*tamper); open(D + "/f.msg", "w").write(txt)
    rc, o, e = sh(VERIFY.format(em=em) + f" -in f.msg {verify_extra} -out /dev/null")
    sig_cert = None
    rc2, o2, e2 = sh(VERIFY.format(em=em) + f" -in f.msg {verify_extra} -signer f_signer.pem -out /dev/null")
    log = []; Counter.n = 0; vdec = vwhy = None
    if os.path.exists(D + "/f_signer.pem") or True:
        try:
            lf = x509.load_pem_x509_certificate(open(D + "/f_signer.pem", "rb").read()) if os.path.exists(D + "/f_signer.pem") and rc2 == 0 else LD(signer)
        except Exception: lf = LD(signer)
        pool = [inter] if certfile is True else []
        roots = [root]
        vdec, vwhy = validate_signer(lf, pool, roots, em, [crl], now, log)
    err = [l for l in e.strip().splitlines() if l.strip()]
    cases.append(dict(id=cid, title=title, predict=predict, rc=rc, openssl_error=err[-1] if err else "", openssl_all=e.strip(), matched=(keyword.lower() in e.lower()),
                      validator=vdec, validator_reason=vwhy, validator_log=log))
    if os.path.exists(D + "/f_signer.pem"): os.remove(D + "/f_signer.pem")
case("S1", "Expired signer certificate", "REJECT at the validity-period check (notAfter < now)", "expired", "userexp", "expired@hospital.test")
case("S2", "Certificate from an untrusted (rogue) CA, claiming user1's address", "REJECT at path building/trust anchor: issuer not in trusted roots", "issuer", "rogueuser", "user1@hospital.test", certfile=False)
case("S3", "Sender address differs from certificate subject (From: user2, cert: user1)", "REJECT at the identity (email) match although chain and signature are valid", "email address mismatch", "user1", "user2@hospital.test")
case("S4", "Revoked certificate (listed on the CRL)", "REJECT at the revocation check", "revoked", "userrev", "revoked@hospital.test")
case("S5", "Tampered message body (one character changed after signing)", "REJECT at the content-digest comparison; chain is fine", "verif", "user1", "user1@hospital.test", tamper=("ab", "ac"))
case("S6", "Intermediate certificate missing from the message", "REJECT at path building: cannot find issuer of the leaf", "issuer", "user1", "user1@hospital.test", certfile=False)
case("S7", "Repair of S6: sender re-sends the same message with the intermediate certificate attached", "ACCEPT - the S6 failure was a missing-chain defect, not a forgery", "successful", "user1", "user1@hospital.test")
res["smime_cases"] = cases
# tamper case: pick a body character that exists
# ------------------------------------------------------------ PGP insufficient-trust case
pt, pi = P.protect(msg4k, "gina", keys["gina"], ring, ["bob"], tnow, P.Ops()); lines = []
try: P.unprotect(pt, "bob", keys["bob"], ring, tnow, P.Ops(), lines.append); res["pgp_untrusted"] = dict(lines=lines, status="UNVALIDATED -> warning, exit code 20")
except P.PgpError as ex: res["pgp_untrusted"] = dict(lines=lines, status=str(ex))
# ------------------------------------------------------------ 2.3 comparison data
smime_ops = dict(sender=dict(sign=1, encrypt_wrap=1), receiver=dict(decrypt=1, content_sig_verify=1, chain_verify=Counter.n and 0))
log = []; Counter.n = 0; validate_signer(leaf1, [inter], [root], "user1@hospital.test", [crl], now, log); chain_and_crl_verifies = Counter.n
res["comparison"] = dict(smime=dict(sender_pk=2, receiver_pk=2 + chain_and_crl_verifies, chain_verifies=chain_and_crl_verifies,
                                    msg_bytes_pem=sizes["a_enc.msg"], msg_bytes_der=sizes["enc_der"], cert_overhead=sizes["leaf_der"] + sizes["inter_der"]),
                         pgp=dict(sender_pk=ops_s.pk, receiver_pk=ops_r.pk, receiver_message_path=2, receiver_key_validation=ops_r.pk - 2, msg_bytes=info["sizes"]["armored"], msg_bytes_bin=info["sizes"]["binary"],
                                  key_overhead=pgp_key_overhead + n_cert_sigs * 256))
# ------------------------------------------------------------ 2.4 scaling model: can a stranger's key be validated?
def model(N, contacts, signers_per_key, p_full=1.0, trials=200000, seed=9):
    rg = random.Random(seed); ok = 0
    for _ in range(trials):
        v = rg.randrange(N); s = rg.randrange(N)
        if v == s: continue
        trusted = set(rg.sample(range(N), contacts))               # introducers the verifier knows and trusts fully (owner-trust full)
        introducers = rg.sample(range(N), signers_per_key)         # people who signed the sender's key
        if any(i in trusted for i in introducers): ok += 1
    return ok / trials
res["scaling"] = [dict(N=5000, contacts=c, signers=k, pgp_valid_fraction=model(5000, c, k)) for c, k in [(20, 5), (50, 10), (200, 10), (500, 20)]]
res["scaling_ca"] = dict(N=5000, valid_fraction=1.0, trust_decisions_per_verifier=1)
json.dump(res, open(R + "/t2.json", "w"), indent=1)
for c in cases: print(c["id"], c["rc"], c["matched"], c["validator"], "|", c["openssl_error"][:110])
print(res["smime_normal"]["steps"]); print(res["smime_normal"]["validator"]["log"]); print(res["comparison"]); print(res["scaling"])
