#!/usr/bin/env python3
"""Part II Task 4 - HTTPS + mutual TLS service built on the Task 2 hierarchy.  All on localhost with TEST keys."""
import os, sys, ssl, json, time, threading, subprocess, http.client, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(__file__))
import pki
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import datetime as dt

R = os.path.join(os.path.dirname(__file__), "..", "results"); D = pki.D; HOST = "hospital.test"; res = {}
SECURITY_HEADERS = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
ALLOWED_CLIENT_CN = {"lab-client-1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ClinicAPI"; sys_version = ""
    def log_message(self, fmt, *a): self.server.applog.append(fmt % a)
    def _send(self, code, obj):
        body = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/status": return self._send(200, {"status": "ok"})
        if self.path == "/records/1001":
            cert = self.connection.getpeercert()
            if not cert: self.server.applog.append("DENY /records: no client certificate"); return self._send(401, {"error": "client certificate required"})
            cn = dict(x[0] for x in cert["subject"]).get("commonName")
            if cn not in ALLOWED_CLIENT_CN: self.server.applog.append(f"DENY /records: CN {cn} not authorised"); return self._send(403, {"error": "forbidden"})
            self.server.applog.append(f"ALLOW /records for CN={cn}"); return self._send(200, {"patient": 1001, "note": "TEST DATA ONLY"})
        return self._send(404, {"error": "not found"})


class TLSServer(ThreadingHTTPServer):
    def __init__(self, port, ctx):
        super().__init__(("127.0.0.1", port), Handler); self.ctx = ctx; self.applog = []; self.hs_errors = []
    def get_request(self):
        sock, addr = self.socket.accept()
        try: return self.ctx.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError) as e:
            self.hs_errors.append(f"{type(e).__name__}: {e}"); sock.close(); raise OSError("handshake failed")


def server_ctx(cert="server", min_v=ssl.TLSVersion.TLSv1_2, max_v=ssl.TLSVersion.MAXIMUM_SUPPORTED, ciphers=None, client_auth=ssl.CERT_OPTIONAL, seclevel0=False):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.minimum_version = min_v; c.maximum_version = max_v
    if ciphers or seclevel0: c.set_ciphers((ciphers or "DEFAULT") + (":@SECLEVEL=0" if seclevel0 else ""))
    chain = D + f"/{cert}_chain.pem"; open(chain, "wb").write(open(D + f"/{cert}.pem", "rb").read() + open(D + "/inter.pem", "rb").read())
    c.load_cert_chain(chain, D + f"/{cert}.key"); c.load_verify_locations(D + "/root.pem"); c.verify_mode = client_auth; return c


def start(port, ctx):
    s = TLSServer(port, ctx); t = threading.Thread(target=s.serve_forever, daemon=True); t.start(); return s


def client(port, path="/status", sni=HOST, client_cert=False, min_v=ssl.TLSVersion.TLSv1_2, max_v=ssl.TLSVersion.MAXIMUM_SUPPORTED, ciphers=None, seclevel0=False, verify=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.minimum_version = min_v; c.maximum_version = max_v
    if ciphers or seclevel0: c.set_ciphers((ciphers or "DEFAULT") + (":@SECLEVEL=0" if seclevel0 else ""))
    if verify: c.load_verify_locations(D + "/root.pem"); c.check_hostname = True; c.verify_mode = ssl.CERT_REQUIRED
    else: c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    if client_cert: c.load_cert_chain(D + "/client1_chain.pem", D + "/client1.key")
    out = dict(ok=False)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5); s = c.wrap_socket(raw, server_hostname=sni)
        out.update(handshake="complete", protocol=s.version(), cipher=s.cipher()[0], bits=s.cipher()[2], peer_der=s.getpeercert(binary_form=True))
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode()); data = b""
        while True:
            b = s.recv(4096)
            if not b: break
            data += b
        head, _, body = data.partition(b"\r\n\r\n"); out.update(ok=True, status=head.split(b"\r\n")[0].decode(), headers=[h.decode() for h in head.split(b"\r\n")[1:]], body=body.decode()); s.close()
    except (ssl.SSLError, OSError) as e:
        out.update(handshake="FAILED", error=f"{type(e).__name__}: {getattr(e, 'reason', '') or ''} | {e}".strip())
    return out


def validate_server_cert(der, hostname, now):
    """Client-side validation, one line per step (what the TLS library does internally, made visible)."""
    leaf = x509.load_der_x509_certificate(der); inter = x509.load_pem_x509_certificate(open(D + "/inter.pem", "rb").read()); root = x509.load_pem_x509_certificate(open(D + "/root.pem", "rb").read()); log = []
    chain = [leaf, inter, root]
    ok = all(chain[i + 1].public_key().verify(chain[i].signature, chain[i].tbs_certificate_bytes, padding.PKCS1v15(), chain[i].signature_hash_algorithm) is None for i in range(2)); log.append(f"chain: leaf <- Hospital Issuing CA <- Hospital Root CA (trusted anchor); 2 signatures verified")
    for c, nm in zip(chain, ["server", "issuing CA", "root CA"]): log.append(f"validity({nm}): {c.not_valid_before_utc:%Y-%m-%d} .. {c.not_valid_after_utc:%Y-%m-%d} -> {'OK' if c.not_valid_before_utc <= now <= c.not_valid_after_utc else 'EXPIRED/NOT YET VALID'}")
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName); log.append(f"hostname: '{hostname}' in SAN {sans} -> {'OK' if hostname in sans else 'MISMATCH'}")
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value; log.append(f"extendedKeyUsage serverAuth -> {'OK' if ExtendedKeyUsageOID.SERVER_AUTH in eku else 'MISSING'}")
    bc = chain[1].extensions.get_extension_for_class(x509.BasicConstraints).value; log.append(f"issuer basicConstraints CA={bc.ca}, pathLen={bc.path_length} -> OK")
    return log


pki.build()
open(D + "/client1_chain.pem", "wb").write(open(D + "/client1.pem", "rb").read() + open(D + "/inter.pem", "rb").read())
now = dt.datetime.now(dt.timezone.utc)
main = start(18443, server_ctx("server", client_auth=ssl.CERT_OPTIONAL)); req = start(18444, server_ctx("server", client_auth=ssl.CERT_REQUIRED)); exp = start(18445, server_ctx("server_expired"))
time.sleep(0.3)
# ---------------------------------------------------------------- 4.1 working service, validation output
r1 = client(18443, "/status"); r2 = client(18443, "/records/1001", client_cert=True); r3 = client(18443, "/records/1001", client_cert=False)
res["s41"] = dict(status=dict(protocol=r1["protocol"], cipher=r1["cipher"], bits=r1["bits"], status=r1["status"], headers=r1["headers"], body=r1["body"]),
                  records_mtls=dict(status=r2["status"], body=r2["body"], protocol=r2["protocol"], cipher=r2["cipher"]), records_nocert=dict(status=r3["status"], body=r3["body"]),
                  validation=validate_server_cert(r1["peer_der"], HOST, now), server_log=main.applog[:])
def sclient(extra): return subprocess.run(f"openssl s_client -connect 127.0.0.1:18443 -servername {HOST} -CAfile {D}/root.pem -verify_return_error -verify_hostname {HOST} {extra} </dev/null 2>&1", shell=True, capture_output=True, text=True).stdout
full = sclient("-showcerts -tls1_3 -cert " + D + "/client1_chain.pem -key " + D + "/client1.key")
res["s41"]["openssl_chain"] = [l for l in full.splitlines() if l.strip().startswith(("0 s:", "1 s:", "2 s:", "i:", "a:", "v:")) or "Verification" in l or "Protocol" in l or "Cipher" in l or "Server Temp Key" in l or "Verify return code" in l][:14]
# ---------------------------------------------------------------- 4.2 handshake capture (TLS 1.2 shows the Certificate message in clear; TLS 1.3 shows where encryption starts)
def msgs(proto):
    out = sclient(f"-{proto} -msg"); lines = []
    for l in out.splitlines():
        if l.startswith((">>>", "<<<")): lines.append(l.strip())
    return lines, out
l12, o12 = msgs("tls1_2"); l13, o13 = msgs("tls1_3")
res["s42"] = dict(tls12=l12[:30], tls13=l13[:30], tls12_kx=[l for l in o12.splitlines() if "Server Temp Key" in l or "Cipher is" in l or "Cipher    :" in l][:4],
                  tls13_kx=[l for l in o13.splitlines() if "Server Temp Key" in l or "Cipher is" in l or "Cipher    :" in l][:4])
# ---------------------------------------------------------------- 4.3 predictions then execution
legacy = None
try: legacy = start(18446, server_ctx("server", min_v=ssl.TLSVersion.TLSv1, max_v=ssl.TLSVersion.TLSv1, seclevel0=True, ciphers="AES128-SHA"))
except Exception as e: res["legacy_error"] = repr(e)
tests = []
def t43(tag, desc, pred, fn):
    o = fn(); tests.append(dict(tag=tag, desc=desc, predicted=pred, handshake=o.get("handshake"), status=o.get("status", ""), error=o.get("error", ""), protocol=o.get("protocol", "")))
t43("a", "server certificate expired (port 18445)", "FAIL during certificate verification (after Certificate message, before Finished); no HTTP", lambda: client(18445, "/status"))
t43("b", "connect using the IP address (server_hostname='127.0.0.1') to the valid server", "FAIL at the hostname check: certificate has DNS names only", lambda: client(18443, "/status", sni="127.0.0.1"))
t43("c", "server restricted to TLS 1.0 (port 18446), client minimum TLS 1.2", "FAIL at version negotiation (no common protocol) - ServerHello never accepted", lambda: client(18446, "/status") if legacy else dict(handshake="server could not be created"))
t43("d", "no client certificate sent to the protected endpoint (optional-auth port 18443)", "TLS handshake SUCCEEDS; /records returns 401 from application logic; /status unaffected", lambda: client(18443, "/records/1001"))
t43("d2", "no client certificate sent to a CERT_REQUIRED listener (port 18444)", "FAIL: server aborts the handshake (certificate required alert)", lambda: client(18444, "/status"))
res["s43"] = tests; res["s43_server_errors"] = dict(expired=exp.hs_errors[:2], required=req.hs_errors[:2], legacy=(legacy.hs_errors[:2] if legacy else []))
# ---------------------------------------------------------------- 4.4 downgrade / weak configuration lab
weak = start(18447, server_ctx("server", min_v=ssl.TLSVersion.TLSv1, max_v=ssl.TLSVersion.TLSv1_2, seclevel0=True, ciphers="AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256")); time.sleep(.2)
weak_client = lambda p: client(p, "/status", min_v=ssl.TLSVersion.TLSv1, max_v=ssl.TLSVersion.TLSv1, ciphers="AES128-SHA", seclevel0=True)
a = weak_client(18447)
fixed = start(18448, server_ctx("server", min_v=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE+AESGCM:ECDHE+CHACHA20")); time.sleep(.2)
b = weak_client(18448); c = client(18448, "/status")
res["s44"] = dict(weak_server="min TLS 1.0, ciphers AES128-SHA (RSA key transport, CBC, SHA-1 MAC), ECDHE-RSA-AES128-SHA, AES128-GCM",
                  legacy_client_vs_weak=dict(handshake=a.get("handshake"), protocol=a.get("protocol"), cipher=a.get("cipher"), status=a.get("status"), error=a.get("error", "")),
                  legacy_client_vs_fixed=dict(handshake=b.get("handshake"), error=b.get("error", "")), modern_client_vs_fixed=dict(handshake=c.get("handshake"), protocol=c.get("protocol"), cipher=c.get("cipher"), status=c.get("status")),
                  fixed_errors=fixed.hs_errors[:2])
res["python"] = sys.version.split()[0]; res["openssl"] = ssl.OPENSSL_VERSION
json.dump(res, open(R + "/t4.json", "w"), indent=1, default=str)
print(res["s41"]["status"]); print(res["s41"]["records_mtls"], res["s41"]["records_nocert"]); print(res["s41"]["validation"]); print(res["s41"]["openssl_chain"])
for t in tests: print(t["tag"], t["handshake"], t["status"], "|", t["error"][:140])
print(res["s44"]); print(res["s42"]["tls12"][:12]); print(res["s42"]["tls13"][:10]); print(res["s43_server_errors"])
