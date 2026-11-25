#!/usr/bin/env python3
"""pki.py - builds a TEST certificate hierarchy: Root CA -> Intermediate CA -> end entities.
Everything is generated at run time into ../work/pki.  Keys are test keys; nothing here protects real data."""
import os, datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

D = os.path.join(os.path.dirname(__file__), "..", "work", "pki"); os.makedirs(D, exist_ok=True)
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def key(bits=2048): return rsa.generate_private_key(public_exponent=65537, key_size=bits)
def name(cn, o="Hospital Test PKI"): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def pem_c(c): return c.public_bytes(serialization.Encoding.PEM)
def pem_k(k): return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
def save(n, c=None, k=None):
    if c is not None: open(f"{D}/{n}.pem", "wb").write(pem_c(c))
    if k is not None: open(f"{D}/{n}.key", "wb").write(pem_k(k)); os.chmod(f"{D}/{n}.key", 0o600)


def ca(cn, issuer_cert=None, issuer_key=None, pathlen=None, days=3650):
    k = key(); subj = name(cn); iss = issuer_cert.subject if issuer_cert else subj
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False))
    if issuer_cert: b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    return b.sign(issuer_key or k, hashes.SHA256()), k


def leaf(cn, issuer_cert, issuer_key, email=None, dns=None, eku=None, nb=None, na=None, ku=None, ips=None):
    k = key(); san = []
    if email: san.append(x509.RFC822Name(email))
    if dns: san += [x509.DNSName(d) for d in dns]
    if ips: import ipaddress; san += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_cert.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb or NOW - dt.timedelta(days=1)).not_valid_after(na or NOW + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(ku or x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False))
    if san: b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(issuer_key, hashes.SHA256()), k


def crl(issuer_cert, issuer_key, revoked_serials):
    b = x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject).last_update(NOW - dt.timedelta(hours=1)).next_update(NOW + dt.timedelta(days=7))
    for s in revoked_serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s).revocation_date(NOW - dt.timedelta(minutes=30)).build())
    return b.sign(issuer_key, hashes.SHA256())


def build():
    root, rk = ca("Hospital Root CA", pathlen=1, days=3650); save("root", root, rk)
    inter, ik = ca("Hospital Issuing CA", root, rk, pathlen=0, days=1825); save("inter", inter, ik)
    S = serialization; ku_enc = x509.KeyUsage(True, False, True, False, False, False, False, False, False)
    ee = {}
    for n, email in [("user1", "user1@hospital.test"), ("user2", "user2@hospital.test"), ("userrev", "revoked@hospital.test")]:
        c, k = leaf(n, inter, ik, email=email, eku=[ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.CLIENT_AUTH]); save(n, c, k); ee[n] = c
    c, k = leaf("userexp", inter, ik, email="expired@hospital.test", nb=NOW - dt.timedelta(days=400), na=NOW - dt.timedelta(days=35)); save("userexp", c, k)
    c, k = leaf("usermis", inter, ik, email="someone.else@hospital.test"); save("usermis", c, k)         # cert subject email differs from the From address
    # untrusted CA: a rogue root the verifier does not trust, issuing a certificate that CLAIMS user1's address
    rroot, rrk = ca("Rogue Root CA"); save("rogueroot", rroot, rrk)
    c, k = leaf("rogue-user1", rroot, rrk, email="user1@hospital.test"); save("rogueuser", c, k)
    # web-service certificates (Task 4)
    srv, sk = leaf("hospital.test", inter, ik, dns=["hospital.test", "api.hospital.test"], eku=[ExtendedKeyUsageOID.SERVER_AUTH]); save("server", srv, sk)
    c, k = leaf("hospital.test", inter, ik, dns=["hospital.test"], eku=[ExtendedKeyUsageOID.SERVER_AUTH], nb=NOW - dt.timedelta(days=400), na=NOW - dt.timedelta(days=35)); save("server_expired", c, k)
    c, k = leaf("lab-client-1", inter, ik, email="labclient@hospital.test", eku=[ExtendedKeyUsageOID.CLIENT_AUTH]); save("client1", c, k)
    revoked = x509.load_pem_x509_certificate(open(f"{D}/userrev.pem", "rb").read()).serial_number
    cl = crl(inter, ik, [revoked]); open(f"{D}/inter.crl.pem", "wb").write(cl.public_bytes(S.Encoding.PEM))
    open(f"{D}/chain.pem", "wb").write(pem_c(inter) + pem_c(root))
    return D


if __name__ == "__main__": print(build())
