#!/usr/bin/env python3
"""esp.py - ESP-like tunnel/transport processing, AH, anti-replay window and an IKE-like key establishment (simulation).
Uses AES-256-GCM (ESP with a combined-mode cipher: the GCM tag is the ICV) and HMAC-SHA256-128 for AH.
All keys come from the IKE-lite exchange at run time (no hard-coded keys)."""
import os, struct, hmac, hashlib, socket, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


def ip2b(a): return socket.inet_aton(a)
def b2ip(b): return socket.inet_ntoa(b)
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack(f">{len(b)//2}H", b)); s = (s & 0xFFFF) + (s >> 16); s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64, ident=1, tos=0):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, tos, 20 + len(payload), ident, 0, ttl, proto, 0, ip2b(src), ip2b(dst))
    return h[:10] + struct.pack(">H", csum(h)) + h[12:] + payload


def parse_ip(p):
    v, tos, tl, ident, ff, ttl, proto, ck, s, d = struct.unpack(">BBHHHBBH4s4s", p[:20])
    return dict(tos=tos, total_len=tl, id=ident, ttl=ttl, proto=proto, checksum=ck, src=b2ip(s), dst=b2ip(d), payload=p[20:tl])


def udp(src, dst, sport, dport, data):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data
    pseudo = ip2b(src) + ip2b(dst) + struct.pack(">BBH", 0, 17, len(seg)); ck = csum(pseudo + seg) or 0xFFFF
    return seg[:6] + struct.pack(">H", ck) + seg[8:]


def udp_ok(src, dst, seg):
    pseudo = ip2b(src) + ip2b(dst) + struct.pack(">BBH", 0, 17, len(seg)); return csum(pseudo + seg) == 0


# ----------------------------------------------------------------------------- IKE-lite
class IkeSession:
    """IKE-like: authenticated ephemeral X25519 (IKE_SA_INIT + IKE_AUTH analogue) -> HKDF -> child SA keys.  Re-keying runs a NEW DH (PFS)."""
    def __init__(self, auth_a, auth_b, sign_a, sign_b, verify_a, verify_b):
        self.auth = (auth_a, auth_b); self.sign = (sign_a, sign_b); self.verify = (verify_a, verify_b); self.log = []; self.generation = 0

    def _exchange(self, label):
        xa, xb = X25519PrivateKey.generate(), X25519PrivateKey.generate(); na, nb = os.urandom(16), os.urandom(16)
        pa, pb = xa.public_key().public_bytes_raw(), xb.public_key().public_bytes_raw()
        transcript = pa + na + pb + nb
        sig_a, sig_b = self.sign[0](transcript + b"A"), self.sign[1](transcript + b"B")                     # authenticate the exchanged values
        ok_a = self.verify[0](transcript + b"A", sig_a); ok_b = self.verify[1](transcript + b"B", sig_b)
        if not (ok_a and ok_b): raise ValueError("IKE authentication failed")
        shared = xa.exchange(xb.public_key()); assert shared == xb.exchange(xa.public_key())
        seed = HKDF(hashes.SHA256(), 32, na + nb, b"ikelite-seed").derive(shared)
        km = HKDF(hashes.SHA256(), 2 * (32 + 4 + 32) + 0, seed, b"ikelite-child").derive(b"child" + struct.pack(">I", self.generation))
        self.log.append(f"{label}: gen={self.generation} DH(X25519) public values exchanged and signed; both signatures verified; keys derived (seed id {hashlib.sha256(seed).hexdigest()[:8]})")
        return km

    def child_sas(self, label="IKE_SA_INIT+IKE_AUTH", lifetime_pkts=None):
        km = self._exchange(label); self.generation += 1
        spi_ab, spi_ba = struct.unpack(">II", os.urandom(8)); spi_ab |= 0x100; spi_ba |= 0x100
        mk = lambda spi, k: dict(spi=spi, key=k[:32], salt=k[32:36], akey=k[36:68])
        a_to_b = mk(spi_ab, km[:68]); b_to_a = mk(spi_ba, km[68:136])
        return a_to_b, b_to_a


class SeqExhausted(Exception): pass


class OutboundSA:
    def __init__(self, d, mode="tunnel", gw_src="192.0.2.1", gw_dst="198.51.100.1", max_seq=0xFFFFFFFF):
        self.spi, self.key, self.salt, self.akey = d["spi"], d["key"], d["salt"], d["akey"]; self.seq = 0; self.mode = mode; self.gw = (gw_src, gw_dst); self.max_seq = max_seq

    def next_seq(self):
        if self.seq >= self.max_seq: raise SeqExhausted(f"SPI {self.spi:#x}: sequence space exhausted at {self.seq}; SA must be re-keyed")
        self.seq += 1; return self.seq

    def protect_tunnel(self, inner):
        seq = self.next_seq(); iv = struct.pack(">Q", seq); pad = (-(len(inner) + 2)) % 4
        plain = inner + bytes(range(1, pad + 1)) + bytes([pad, 4]); hdr = struct.pack(">II", self.spi, seq)
        ct = AESGCM(self.key).encrypt(self.salt + iv, plain, hdr)                          # ciphertext || 16-byte ICV
        return ipv4(self.gw[0], self.gw[1], 50, hdr + iv + ct)

    def protect_transport(self, ip_pkt):
        """ESP transport: IP header kept (proto becomes 50); only the payload is protected."""
        f = parse_ip(ip_pkt); seq = self.next_seq(); iv = struct.pack(">Q", seq); payload = f["payload"]; pad = (-(len(payload) + 2)) % 4
        plain = payload + bytes(range(1, pad + 1)) + bytes([pad, f["proto"]]); hdr = struct.pack(">II", self.spi, seq)
        ct = AESGCM(self.key).encrypt(self.salt + iv, plain, hdr)
        return ipv4(f["src"], f["dst"], 50, hdr + iv + ct, ttl=f["ttl"], ident=f["id"])

    def protect_ah(self, ip_pkt):
        """AH transport: ICV over immutable IP fields (version/IHL, total length, src, dst) + AH header (ICV zeroed) + payload.
        Mutable fields (TOS, TTL, flags/fragment offset, header checksum) are excluded from the computation."""
        f = parse_ip(ip_pkt); seq = self.next_seq(); l4 = f["payload"]; ahh = struct.pack(">BBHII", f["proto"], 4, 0, self.spi, seq)
        icv = ah_icv(self.akey, f["src"], f["dst"], 20 + 24 + len(l4), ahh, l4)
        return ipv4(f["src"], f["dst"], 51, ahh + icv + l4, ttl=f["ttl"], ident=f["id"])


def ah_icv(akey, src, dst, total_len, ahh, l4):
    data = struct.pack(">BH4s4s", 0x45, total_len, ip2b(src), ip2b(dst)) + ahh + bytes(12) + l4
    return hmac.new(akey, data, hashlib.sha256).digest()[:12]


def verify_ah(pkt, akey):
    f = parse_ip(pkt); body = f["payload"]; ahh, icv, l4 = body[:12], body[12:24], body[24:]
    return hmac.compare_digest(icv, ah_icv(akey, f["src"], f["dst"], f["total_len"], ahh, l4)), l4


def esp_transport_open(pkt, sa):
    f = parse_ip(pkt); body = f["payload"]; spi, seq = struct.unpack(">II", body[:8])
    try: plain = AESGCM(sa.key).decrypt(sa.salt + body[8:16], body[16:], body[:8])
    except InvalidTag: return False, None, f
    pad, nh = plain[-2], plain[-1]; return True, plain[:len(plain) - 2 - pad], f


def nat_rewrite_src(pkt, new_src):
    f = parse_ip(pkt); return ipv4(new_src, f["dst"], f["proto"], f["payload"], ttl=f["ttl"], ident=f["id"])


class InboundSA:
    """Receiver state for ONE SA: Highest and Window (bit i set <=> sequence number Highest-i has been received)."""
    def __init__(self, d, W=32, mode="tunnel"):
        self.spi, self.key, self.salt, self.akey = d["spi"], d["key"], d["salt"], d["akey"]; self.W = W; self.highest = 0; self.mask = 0; self.mode = mode

    def replay_state(self, seq):
        if seq == 0: return "ZERO"
        if seq > self.highest: return "NEW"
        d = self.highest - seq
        if d >= self.W: return "TOO_OLD"
        return "DUPLICATE" if (self.mask >> d) & 1 else "IN_WINDOW_UNSEEN"

    def update(self, seq):
        if seq > self.highest:
            shift = seq - self.highest; self.mask = ((self.mask << shift) | 1) & ((1 << self.W) - 1) if shift < self.W else 1; self.highest = seq
        else: self.mask |= 1 << (self.highest - seq)

    def window_seqs(self): return [self.highest - i for i in range(self.W) if (self.mask >> i) & 1]


class Gateway:
    """Inbound ESP tunnel-mode processor.  Order: SA lookup -> ICV -> replay check -> window update -> decapsulate.
    External behaviour of every drop is identical (silent discard); the specific reason goes to the internal log only."""
    def __init__(self): self.sad = {}; self.log = []; self.dummy = AESGCM(os.urandom(32))
    def add(self, sa): self.sad[sa.spi] = sa

    def process(self, pkt):
        t = time.perf_counter(); outer = parse_ip(pkt); body = outer["payload"]
        if outer["proto"] != 50 or len(body) < 8 + 8 + 16 + 4: return self._drop("MALFORMED", None, 0, t)
        spi, seq = struct.unpack(">II", body[:8]); iv = body[8:16]; ct = body[16:]
        sa = self.sad.get(spi)
        if sa is None:                                              # unknown SPI: do a dummy ICV computation so the timing profile matches other drops
            try: self.dummy.decrypt(b"\0" * 12, ct, body[:8])
            except InvalidTag: pass
            return self._drop("UNKNOWN_SPI", spi, seq, t)
        try: plain = AESGCM(sa.key).decrypt(sa.salt + iv, ct, body[:8])              # ICV verified BEFORE any state is read or written
        except InvalidTag: return self._drop("ICV_FAIL", spi, seq, t, sa)
        rs = sa.replay_state(seq)
        if rs not in ("NEW", "IN_WINDOW_UNSEEN"): return self._drop({"ZERO": "SEQ_ZERO", "TOO_OLD": "REPLAY_TOO_OLD", "DUPLICATE": "REPLAY_DUPLICATE"}[rs], spi, seq, t, sa)
        sa.update(seq)                                                              # state changes only for an authentic, fresh packet
        pad, nh = plain[-2], plain[-1]; inner = plain[:len(plain) - 2 - pad]
        self.log.append(dict(decision="ACCEPT", reason=rs, spi=spi, seq=seq, highest=sa.highest, window=sa.window_seqs(), icv="valid", inner=inner, dt=time.perf_counter() - t))
        return self.log[-1]

    def _drop(self, reason, spi, seq, t, sa=None):
        rec = dict(decision="DROP", reason=reason, spi=spi, seq=seq, highest=(sa.highest if sa else None), window=(sa.window_seqs() if sa else None), icv=("invalid" if reason == "ICV_FAIL" else ("valid" if sa else "n/a")), dt=time.perf_counter() - t)
        self.log.append(rec); return rec
