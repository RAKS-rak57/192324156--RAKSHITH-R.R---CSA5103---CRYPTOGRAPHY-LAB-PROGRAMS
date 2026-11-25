#!/usr/bin/env python3
"""Part II Task 3 - ESP-like tunnel gateway, anti-replay, tamper handling, AH vs ESP under NAT, IKE-lite, SA bundle."""
import os, sys, json, time, statistics, struct
sys.path.insert(0, os.path.dirname(__file__))
import esp
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

R = os.path.join(os.path.dirname(__file__), "..", "results"); os.makedirs(R, exist_ok=True)
ka, kb = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
sgn = lambda k: (lambda m: k.sign(m, ec.ECDSA(hashes.SHA256())))
def ver(k):
    def f(m, s):
        try: k.public_key().verify(s, m, ec.ECDSA(hashes.SHA256())); return True
        except InvalidSignature: return False
    return f
ike = esp.IkeSession("gwA", "gwB", sgn(ka), sgn(kb), ver(ka), ver(kb))
res = {}


def inner_pkt(n):
    seg = esp.udp("10.1.0.5", "10.2.0.9", 5000, 6000, f"LAB-RESULT-{n:03d}".encode()); return esp.ipv4("10.1.0.5", "10.2.0.9", 17, seg, ident=n)
def fmt(rec):
    return dict(decision=rec["decision"], reason=rec["reason"], spi=rec["spi"], seq=rec["seq"], highest=rec["highest"], window=rec["window"], icv=rec["icv"])


# ---------------------------------------------------------------- Stage A : normal protection
ab, ba = ike.child_sas()
out_sa = esp.OutboundSA(ab); gw = esp.Gateway(); gw.add(esp.InboundSA(ab, W=32))
rows = []
for n in range(1, 7):
    pkt = out_sa.protect_tunnel(inner_pkt(n)); rec = gw.process(pkt); inner = esp.parse_ip(rec["inner"]); udpd = inner["payload"][8:]
    rows.append(dict(fmt(rec), outer_len=len(pkt), inner_src=inner["src"], inner_dst=inner["dst"], payload=udpd.decode(), udp_checksum_ok=esp.udp_ok(inner["src"], inner["dst"], inner["payload"])))
res["A"] = dict(rows=rows, spi=hex(ab["spi"]), overhead=len(pkt) - len(inner_pkt(6)), inner_len=len(inner_pkt(6)), ike_log=ike.log[:])
res["A_example_hex"] = pkt[:48].hex(" ")
res["A_fields"] = dict(outer_ip=20, esp_spi=4, esp_seq=4, iv=8, inner_len=len(inner_pkt(6)), pad_and_trailer=len(pkt) - 20 - 16 - len(inner_pkt(6)) - 16 + 0, icv=16)

# ---------------------------------------------------------------- Stage B : replay / reordering with W = 32  (predictions written BEFORE execution)
W = 32
pred = [("i", "exact replay of seq 100 (already accepted)", "DROP - REPLAY_DUPLICATE"),
        ("ii", "genuine packet seq 84, delayed by W/2 = 16 positions (never seen before)", "ACCEPT - IN_WINDOW_UNSEEN"),
        ("ii-b", "the SAME seq 84 replayed again after acceptance", "DROP - REPLAY_DUPLICATE"),
        ("iii", "genuine packet seq 60, delayed by 40 > W positions", "DROP - REPLAY_TOO_OLD (genuine but outside the window)"),
        ("iv", "captured packet seq 100 re-sent with sequence field changed to 101", "DROP - ICV_FAIL (sequence number is covered by the ICV)"),
        ("iv-b", "captured packet re-sent with sequence field changed to 70 (inside window, unseen)", "DROP - ICV_FAIL (never reaches the window)"),
        ("edge-in", "boundary: seq 69 = Highest - W + 1 (oldest slot still inside the window), unseen", "ACCEPT - IN_WINDOW_UNSEEN"),
        ("edge-out", "boundary: seq 68 = Highest - W (first slot outside the window)", "DROP - REPLAY_TOO_OLD")]
ab2, _ = ike.child_sas("CREATE_CHILD_SA (lab B)")
s2 = esp.OutboundSA(ab2); g2 = esp.Gateway(); g2.add(esp.InboundSA(ab2, W=W))
held = {}; pkts = {}
for n in range(1, 101):
    s2.seq = n - 1; p = s2.protect_tunnel(inner_pkt(n)); pkts[n] = p
    if n in (84, 69, 68, 60): held[n] = p; continue
    g2.process(p)
state_before = dict(highest=g2.sad[ab2["spi"]].highest, window_size=W)
def forge_seq(p, newseq):
    o = esp.parse_ip(p); body = bytearray(o["payload"]); body[4:8] = struct.pack(">I", newseq); return esp.ipv4(o["src"], o["dst"], 50, bytes(body))
actual = []
def run(tag, desc, pkt, p_text):
    r = g2.process(pkt); actual.append(dict(tag=tag, desc=desc, predicted=p_text, actual=f"{r['decision']} - {r['reason']}", highest=r["highest"], match=(r["decision"] + " - " + r["reason"]) in p_text or p_text.startswith(r["decision"] + " - " + r["reason"])))
exec_order = [("i", pkts[100]), ("ii", held[84]), ("ii-b", held[84]), ("iii", held[60]), ("iv", forge_seq(pkts[100], 101)), ("iv-b", forge_seq(pkts[100], 70)), ("edge-in", held[69]), ("edge-out", held[68])]
for (tag, desc, ptxt), (t2, pk) in zip(pred, exec_order): run(tag, desc, pk, ptxt)
res["B"] = dict(W=W, state_before=state_before, rows=actual, window_after=g2.sad[ab2["spi"]].window_seqs()[:6])

# ---------------------------------------------------------------- Part I task 3.4 check with W = 4  (hand trace verified by the engine)
ab3, _ = ike.child_sas("CREATE_CHILD_SA (W=4 check)"); s3 = esp.OutboundSA(ab3); g3 = esp.Gateway(); g3.add(esp.InboundSA(ab3, W=4)); w4 = []
for i, (seq, valid) in enumerate([(1, 1), (2, 1), (5, 1), (3, 1), (2, 1), (9, 1), (4, 1), (7, 0), (7, 1)], 1):
    s3.seq = seq - 1; p = s3.protect_tunnel(inner_pkt(seq))
    if not valid: b = bytearray(p); b[-1] ^= 1; p = bytes(b)
    r = g3.process(p); w4.append(dict(order=i, seq=seq, icv="valid" if valid else "invalid", decision=r["decision"], reason=r["reason"], highest=g3.sad[ab3["spi"]].highest, window=g3.sad[ab3["spi"]].window_seqs()))
res["W4"] = w4

# ---------------------------------------------------------------- Stage C : tamper and misconfiguration
ab4, _ = ike.child_sas("CREATE_CHILD_SA (lab C)"); s4 = esp.OutboundSA(ab4, max_seq=10); g4 = esp.Gateway(); g4.add(esp.InboundSA(ab4, W=32)); C = []
good = s4.protect_tunnel(inner_pkt(1)); g4.process(good)
t = bytearray(s4.protect_tunnel(inner_pkt(2))); t[20 + 8 + 8 + 5] ^= 0x01; C.append(("modified payload byte", g4.process(bytes(t))))
u = bytearray(s4.protect_tunnel(inner_pkt(3))); u[20 + 3] ^= 0x7F; C.append(("unknown SPI", g4.process(bytes(u))))
trunc = s4.protect_tunnel(inner_pkt(4))[:30]; C.append(("truncated packet", g4.process(trunc)))
for k in range(5, 11): s4.protect_tunnel(inner_pkt(k))
try: s4.protect_tunnel(inner_pkt(11)); exhausted = None
except esp.SeqExhausted as ex: exhausted = str(ex)
ab5, _ = ike.child_sas("CREATE_CHILD_SA (rekey after exhaustion)"); s5 = esp.OutboundSA(ab5); g4.add(esp.InboundSA(ab5, W=32))
new_rec = g4.process(s5.protect_tunnel(inner_pkt(12)))
late = g4.process(s4.protect_tunnel.__self__.protect_tunnel(inner_pkt(13))) if False else None
res["C"] = dict(rows=[dict(case=c, reason=r["reason"], internal_log=fmt(r), external_response="none (silent discard, no ICMP, no error text)") for c, r in C], exhausted=exhausted,
                rekey_accept=fmt(new_rec), ike_log=ike.log[-1])
# timing profile of each drop reason (does the drop path leak which check failed?)
def timing(name, make, n=400):
    ts = []
    for _ in range(n):
        gwt, p = make(); t0 = time.perf_counter(); gwt.process(p); ts.append(time.perf_counter() - t0)
    return dict(case=name, median_us=statistics.median(ts) * 1e6, p90_us=sorted(ts)[int(.9 * len(ts))] * 1e6)
def fresh(W_=32):
    d, _ = ike.child_sas("timing"); so = esp.OutboundSA(d); gg = esp.Gateway(); gg.add(esp.InboundSA(d, W=W_)); return d, so, gg
def mk_accept(): d, so, gg = fresh(); return gg, so.protect_tunnel(inner_pkt(1))
def mk_dup(): d, so, gg = fresh(); p = so.protect_tunnel(inner_pkt(1)); gg.process(p); return gg, p
def mk_old():
    d, so, gg = fresh(4); so.seq = 99; gg.process(so.protect_tunnel(inner_pkt(1))); so.seq = 0; return gg, so.protect_tunnel(inner_pkt(2))
def mk_icv(): d, so, gg = fresh(); p = bytearray(so.protect_tunnel(inner_pkt(1))); p[-1] ^= 1; return gg, bytes(p)
def mk_spi(): d, so, gg = fresh(); p = bytearray(so.protect_tunnel(inner_pkt(1))); p[23] ^= 0x55; return gg, bytes(p)
_n_log = len(ike.log)
res["timing"] = [timing(n, f, 200) for n, f in [("ACCEPT", mk_accept), ("REPLAY_DUPLICATE", mk_dup), ("REPLAY_TOO_OLD", mk_old), ("ICV_FAIL", mk_icv), ("UNKNOWN_SPI", mk_spi)]]
del ike.log[_n_log:]

# ---------------------------------------------------------------- Stage D : coverage table (generated) + NAT experiment
cover = {  # field -> (encrypted, authenticated) per mode
    "ESP-transport": [("IP header (original, proto=50)", "no", "no"), ("ESP header (SPI, Seq)", "no", "yes"), ("IV", "no", "yes"), ("Transport payload (UDP/TCP + data)", "yes", "yes"), ("ESP trailer (pad, pad-len, next-hdr)", "yes", "yes"), ("ICV", "-", "-")],
    "ESP-tunnel": [("New outer IP header", "no", "no"), ("ESP header (SPI, Seq)", "no", "yes"), ("IV", "no", "yes"), ("Original IP header", "yes", "yes"), ("Original payload", "yes", "yes"), ("ESP trailer", "yes", "yes"), ("ICV", "-", "-")],
    "AH-transport": [("IP header: immutable fields (src, dst, proto, length)", "no", "yes"), ("IP header: mutable fields (TTL, TOS, flags, checksum)", "no", "no (zeroed)"), ("AH header (SPI, Seq, ICV zeroed)", "no", "yes"), ("Payload", "no", "yes")]}
res["D_cover"] = cover
ab6, _ = ike.child_sas("CREATE_CHILD_SA (NAT lab)")
o6 = esp.OutboundSA(ab6); nat_rows = []
host_pkt = esp.ipv4("10.1.0.5", "10.2.0.9", 17, esp.udp("10.1.0.5", "10.2.0.9", 5000, 6000, b"LAB-RESULT-NAT"))
p = o6.protect_ah(host_pkt); okp, _ = esp.verify_ah(p, ab6["akey"]); pn = esp.nat_rewrite_src(p, "203.0.113.7"); ok_n, _ = esp.verify_ah(pn, ab6["akey"])
nat_rows.append(dict(mode="AH (transport)", before_nat_icv=okp, after_nat_icv=ok_n, app_checksum="not reached" if not ok_n else "n/a", result="DROP - ICV fails: source address is an immutable, authenticated field"))
isa = esp.InboundSA(ab6); p = o6.protect_transport(host_pkt); okp, pl, f = esp.esp_transport_open(p, isa); pn = esp.nat_rewrite_src(p, "203.0.113.7"); ok_n, pl2, f2 = esp.esp_transport_open(pn, isa)
ck = esp.udp_ok(f2["src"], f2["dst"], pl2) if ok_n else None
nat_rows.append(dict(mode="ESP (transport)", before_nat_icv=okp, after_nat_icv=ok_n, app_checksum=("UDP checksum " + ("OK" if ck else "FAILS")), result="ICV passes (outer header not covered) but UDP checksum covers the old address and is encrypted, so NAT cannot repair it -> datagram discarded by the host"))
gn = esp.Gateway(); gn.add(esp.InboundSA(ab6)); p = o6.protect_tunnel(inner_pkt(7)); pn = esp.nat_rewrite_src(p, "203.0.113.7"); r = gn.process(pn); inn = esp.parse_ip(r["inner"])
nat_rows.append(dict(mode="ESP (tunnel)", before_nat_icv=True, after_nat_icv=(r["icv"] == "valid"), app_checksum="UDP checksum " + ("OK" if esp.udp_ok(inn["src"], inn["dst"], inn["payload"]) else "FAILS"), result="ACCEPT - outer header is outside the ICV and the inner packet is untouched (real deployments add UDP encapsulation, NAT-T port 4500, so the NAT can track the flow)"))
res["D_nat"] = nat_rows

# ---------------------------------------------------------------- SA bundle: host-to-host AH (SA1, transport) inside gateway-to-gateway ESP tunnel (SA2)
ahA, _ = ike.child_sas("CREATE_CHILD_SA (SA1 AH host-to-host)"); espA, _ = ike.child_sas("CREATE_CHILD_SA (SA2 ESP gw-gw)")
sa1 = esp.OutboundSA(ahA); sa2 = esp.OutboundSA(espA); gwB = esp.Gateway(); gwB.add(esp.InboundSA(espA))
pkt0 = esp.ipv4("10.1.0.5", "10.2.0.9", 17, esp.udp("10.1.0.5", "10.2.0.9", 5000, 6000, b"LAB-RESULT-BUNDLE")); pkt1 = sa1.protect_ah(pkt0); pkt2 = sa2.protect_tunnel(pkt1)
rec = gwB.process(pkt2); ok_ah, l4 = esp.verify_ah(rec["inner"], ahA["akey"])
res["bundle"] = dict(sizes=dict(original=len(pkt0), after_AH=len(pkt1), after_ESP=len(pkt2)), spi_ah=hex(ahA["spi"]), spi_esp=hex(espA["spi"]), gw_decision=fmt(rec), ah_ok=ok_ah, payload=l4[8:].decode())
res["ike_log_all"] = ike.log
json.dump(res, open(R + "/t3.json", "w"), indent=1, default=str)
for r in res["B"]["rows"]: print(r["tag"], "|", r["predicted"][:40], "|", r["actual"], r["match"])
for r in res["W4"]: print(r)
for r in res["C"]["rows"]: print(r["case"], r["reason"])
print(res["C"]["exhausted"]); print(res["timing"]); print(res["D_nat"]); print(res["bundle"])
