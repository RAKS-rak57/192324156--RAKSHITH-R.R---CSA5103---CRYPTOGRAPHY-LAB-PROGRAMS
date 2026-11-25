#!/usr/bin/env python3
import json, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, FancyArrowPatch

B = os.path.join(os.path.dirname(__file__), ".."); R = B + "/results"; F = B + "/fig"; os.makedirs(F, exist_ok=True)
L = lambda n: json.load(open(f"{R}/{n}.json"))
C = dict(blue="#DCE9F7", green="#DDF0DD", orange="#FCE8CF", red="#F8D7D7", grey="#EEEEEE", purple="#E8DFF3", dark="#1F3A5F")
plt.rcParams.update({"font.size": 9, "font.family": "DejaVu Sans"})


def box(ax, x, y, w, h, txt, fc="blue", fs=8.5, bold=False, ec="#555"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=C.get(fc, fc), ec=ec, lw=1))
    ax.text(x + w / 2, y + h / 2, txt, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal", wrap=True)
def arrow(ax, x1, y1, x2, y2, txt=None, color="#333", style="-|>", rad=0, fs=7.5, ty=0.08, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=11, color=color, lw=1.2, connectionstyle=f"arc3,rad={rad}", linestyle=ls))
    if txt: ax.text((x1 + x2) / 2, (y1 + y2) / 2 + ty, txt, ha="center", va="bottom", fontsize=fs, color=color)
def canvas(w, h, name=None):
    fig, ax = plt.subplots(figsize=(w, h)); ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off"); return fig, ax
def save(fig, name): fig.savefig(f"{F}/{name}.png", dpi=170, bbox_inches="tight", facecolor="white"); plt.close(fig)


# ---------------------------------------------------------------- 1 PGP flow (Part I Task 2)
fig, ax = canvas(9.2, 5.2)
ax.text(4.6, 5.0, "Sender (Alice)", ha="center", fontweight="bold", color=C["dark"]); ax.text(4.6, 2.6, "Receiver (Bob)", ha="center", fontweight="bold", color=C["dark"])
s = [("M", "orange"), ("HASH\n+ SIGN\n(KRa)", "blue"), ("COMPRESS\nsig | M", "green"), ("SYM_ENCRYPT\n(Ks)", "purple"), ("RADIX-64", "grey")]
x = 0.2
for i, (t, c) in enumerate(s):
    box(ax, x, 3.55, 1.45, 1.05, t, c); 
    if i: arrow(ax, x - 0.25, 4.07, x, 4.07)
    x += 1.75
ax.text(7.3, 4.85, "Ks = RANDOM_KEY (one per message)", fontsize=7.5, color="#444")
arrow(ax, 7.3, 4.78, 6.0, 4.6, ls="--", color="#777")
box(ax, 6.3, 3.0, 2.0, 0.55, "PK_ENCRYPT(KUb, Ks)\n= wrapped key", "blue", fs=8)
arrow(ax, 6.2, 4.7, 7.0, 3.58, color="#777", ls="--")
ax.text(8.9, 4.12, "→ email", fontsize=9, fontweight="bold")
r = [("RADIX-64\ndecode", "grey"), ("SYM_DECRYPT\n(Ks)", "purple"), ("DECOMPRESS", "green"), ("split\nsig | M", "orange"), ("HASH + VERIFY\n(KUa)", "blue")]
x = 0.2
for i, (t, c) in enumerate(r):
    box(ax, x, 0.8, 1.45, 1.05, t, c)
    if i: arrow(ax, x - 0.25, 1.32, x, 1.32)
    x += 1.75
box(ax, 0.2, 1.95, 2.0, 0.55, "PK_DECRYPT(KRb,\nwrapped) → Ks", "blue", fs=8); arrow(ax, 1.2, 1.95, 2.55, 1.85, color="#777", ls="--")
ax.text(4.6, 0.35, "ACCEPT only if every check passes; any failure → discard, log reason, report nothing useful to the sender", ha="center", fontsize=8, style="italic")
save(fig, "p1_pgp_flow")

# ---------------------------------------------------------------- 2 protected message layout (T1.2)
t1 = L("t1"); fig, ax = canvas(10.6, 2.6)
parts = [("magic\n4", 0.45, "grey"), ("ver\n1", 0.3, "grey"), ("nrec\n2", 0.35, "grey"), ("Ks id\n8", 0.7, "orange"), ("sender\nkeyid 8", 0.85, "orange"), ("rcpt keyid 8 | len 2", 1.3, "blue"), ("RSA-OAEP wrapped Ks\n256 B", 2.0, "blue"), ("nonce\n12", 0.6, "purple"), ("len 4", 0.4, "grey"), ("AES-256-GCM ciphertext + 16 B tag\n(compressed(sig 256 | M))", 3.1, "green")]
x = 0.1
for t, w, c in parts: box(ax, x, 0.9, w, 0.9, t, c, fs=7); x += w + 0.04
ax.annotate("", xy=(0.1, 0.7), xytext=(5.8, 0.7), arrowprops=dict(arrowstyle="<->")); ax.text(2.9, 0.4, "header (authenticated as AAD) — 289 B for one recipient", ha="center", fontsize=8)
ax.annotate("", xy=(5.9, 0.7), xytext=(10.5, 0.7), arrowprops=dict(arrowstyle="<->")); ax.text(8.2, 0.4, "nonce, length, ciphertext", ha="center", fontsize=8)
ax.text(5.3, 2.2, "Protected message structure (binary, before radix-64)", ha="center", fontweight="bold")
save(fig, "t1_layout")

# ---------------------------------------------------------------- 3 T1 sizes bar
m = t1["meas"]; fig, ax = plt.subplots(figsize=(6.2, 3.1)); cs = ["a\n1 rcpt, 4 KB", "b\n5 rcpt, 4 KB", "c\n1 rcpt, 40 KB"]
hs = [m[k]["sizes"]["header"] for k in "abc"]; cts = [m[k]["sizes"]["ciphertext"] for k in "abc"]
ax.bar(cs, hs, color="#9DB9DD", label="header (recipient entries)"); ax.bar(cs, cts, bottom=hs, color="#9FD09F", label="compressed + encrypted payload")
for i, k in enumerate("abc"): ax.text(i, hs[i] + cts[i] + 150, f"{m[k]['sizes']['binary']} B\npk={m[k]['pk']} sym={m[k]['sym']}", ha="center", fontsize=8)
ax.set_ylabel("bytes"); ax.set_ylim(0, 12500); ax.legend(fontsize=7.5, loc="upper left"); ax.set_title("Task 1.3 — protected-message size and operation counts", fontsize=9)
save(fig, "t1_sizes")

# ---------------------------------------------------------------- 4 replay window W=4 trace (Part I 3.4)
t3 = L("t3"); w4 = t3["W4"]; fig, ax = plt.subplots(figsize=(8.8, 3.6)); ax.set_xlim(0, 10.5); ax.set_ylim(0, len(w4) + 1.2); ax.axis("off")
for r, e in enumerate(w4):
    y = len(w4) - r - 0.2; ax.text(0, y + .25, f"#{e['order']}  seq {e['seq']} ({'ICV ok' if e['icv']=='valid' else 'ICV BAD'})", fontsize=7.5, va="center")
    for s in range(1, 11):
        inwin = e["highest"] - 3 <= s <= e["highest"] and e["highest"] > 0; got = s in e["window"]
        ax.add_patch(Rectangle((2.6 + (s - 1) * .75, y), .7, .5, fc=("#9FD09F" if got else ("#FFF5D6" if inwin else "#FFFFFF")), ec="#999", lw=.7)); ax.text(2.6 + (s - 1) * .75 + .35, y + .25, str(s), ha="center", va="center", fontsize=7)
    ax.text(10.15, y + .25, ("✔ " if e["decision"] == "ACCEPT" else "✘ ") + e["decision"], fontsize=7.5, va="center", color=("#1B6B1B" if e["decision"] == "ACCEPT" else "#A02020"))
ax.text(2.6, len(w4) + .6, "green = received   yellow = inside window, not yet received   white = outside window", fontsize=7)
save(fig, "p3_window")

# ---------------------------------------------------------------- 5 window boundary W=32 (Stage B)
fig, ax = canvas(9.4, 2.7)
ax.add_patch(Rectangle((0.5, 1.2), 6.4, 0.5, fc="#E9F4E9", ec="#555")); ax.add_patch(Rectangle((0.2, 1.2), 0.3, 0.5, fc="#F8D7D7", ec="#555"))
ax.text(0.2, 1.8, "seq ≤ 68\nTOO OLD", fontsize=7.5, color="#A02020"); ax.text(3.7, 1.8, "window: seq 69 … 100  (W = 32)", ha="center", fontsize=8.5)
pos = {60: 0.1, 68: 0.3, 69: 0.55, 84: 3.5, 100: 6.7}
for sq, px in pos.items():
    ax.plot([px + .12], [1.45], marker="v", color="#1F3A5F"); ax.text(px + .12, 1.0, str(sq), ha="center", fontsize=8)
ax.text(0.12, 0.6, "60: DROP", fontsize=7, color="#A02020"); ax.text(0.7, 0.4, "68: DROP (edge-out)", fontsize=7, color="#A02020"); ax.text(1.6, 0.6, "69: ACCEPT (edge-in)", fontsize=7, color="#1B6B1B")
ax.text(3.5, 0.6, "84: ACCEPT (W/2 late)", fontsize=7, color="#1B6B1B"); ax.text(6.0, 0.6, "100 = Highest", fontsize=7)
ax.text(4.7, 2.5, "Stage B — window state after packets 1..100 (60, 68, 69, 84 withheld)", ha="center", fontweight="bold")
save(fig, "t3_boundary")

# ---------------------------------------------------------------- 6 packet formats (Stage D)
fig, ax = canvas(9.6, 5.4)
def row(y, label, cells):
    ax.text(0.0, y + .28, label, fontsize=8.2, fontweight="bold", va="center"); x = 1.55
    for t, w, kind in cells:
        fc = {"enc": "#DDF0DD", "auth": "#DCE9F7", "none": "#F8D7D7", "mix": "#EEE"}[kind]; ax.add_patch(Rectangle((x, y), w, .56, fc=fc, ec="#555")); ax.text(x + w / 2, y + .28, t, ha="center", va="center", fontsize=6.8); x += w
row(4.4, "ESP\ntransport", [("IP hdr", .9, "none"), ("ESP hdr\nSPI|Seq", .95, "auth"), ("IV", .45, "auth"), ("UDP/TCP + data", 2.3, "enc"), ("trailer", .75, "enc"), ("ICV", .6, "mix")])
row(3.3, "ESP\ntunnel", [("new IP", .9, "none"), ("ESP hdr", .75, "auth"), ("IV", .4, "auth"), ("orig IP hdr", .95, "enc"), ("payload", 1.5, "enc"), ("trailer", .7, "enc"), ("ICV", .55, "mix")])
row(2.2, "AH\ntransport", [("IP hdr\n(mutable\nzeroed)", 1.05, "auth"), ("AH hdr\nSPI|Seq|ICV", 1.3, "auth"), ("payload (readable)", 2.9, "auth")])
ax.add_patch(Rectangle((1.55, 1.2), .3, .3, fc="#DDF0DD", ec="#555")); ax.text(1.95, 1.35, "encrypted + authenticated", fontsize=7.5, va="center")
ax.add_patch(Rectangle((4.1, 1.2), .3, .3, fc="#DCE9F7", ec="#555")); ax.text(4.5, 1.35, "authenticated only", fontsize=7.5, va="center")
ax.add_patch(Rectangle((6.2, 1.2), .3, .3, fc="#F8D7D7", ec="#555")); ax.text(6.6, 1.35, "neither (not covered)", fontsize=7.5, va="center")
ax.text(4.8, 5.2, "Protection coverage (generated from the program's field table)", ha="center", fontweight="bold"); ax.text(4.8, .65, "The ICV of ESP covers the ESP header, IV, payload and trailer — never the outer IP header. AH's ICV covers the immutable IP fields.", ha="center", fontsize=7.5, style="italic")
save(fig, "t3_formats")

# ---------------------------------------------------------------- 7 IKE sequence + SA bundle
fig, ax = canvas(9.2, 5.0); ax.text(4.6, 4.8, "IKE-style establishment, authentication and re-keying", ha="center", fontweight="bold")
for x, n in [(1.6, "Gateway A (lab)"), (7.6, "Gateway B (branch)")]: box(ax, x - .9, 4.15, 1.8, .45, n, "blue", bold=True); ax.plot([x, x], [.3, 4.15], color="#888", lw=1)
msgs = [(3.7, "IKE_SA_INIT: DH public value gᵃ, nonce Nᵃ  →", 1), (3.25, "←  gᵇ, Nᵇ   (both derive SKEYSEED = HKDF(gᵃᵇ, Nᵃ|Nᵇ))", -1), (2.75, "IKE_AUTH: identity + certificate + SIGN(transcript)  →   (encrypted with IKE-SA keys)", 1), (2.3, "←  identity + certificate + SIGN(transcript); child SA proposal, SPIs", -1),
        (1.7, "CREATE_CHILD_SA (re-key): NEW DH + nonces + new SPI  →", 1), (1.25, "←  new DH + nonce ; old SA kept until its lifetime ends, then deleted", -1)]
for y, t, d in msgs: arrow(ax, 1.6 if d > 0 else 7.6, y, 7.6 if d > 0 else 1.6, y); ax.text(4.6, y + .06, t, ha="center", fontsize=7.2)
ax.text(4.6, .55, "Result: two unidirectional ESP SAs (SPI_AB, SPI_BA), each with its own enc/auth keys and a sequence counter starting at 0", ha="center", fontsize=7.8, style="italic")
save(fig, "t3_ike")
fig, ax = canvas(9.2, 3.2); ax.text(4.6, 3.0, "SA bundle traced in the experiment: AH (transport, host-to-host) inside ESP (tunnel, gateway-to-gateway)", ha="center", fontweight="bold", fontsize=8.5)
box(ax, .2, 1.8, 1.4, .8, "Host A\n10.1.0.5", "orange"); box(ax, 2.0, 1.8, 1.5, .8, "Gateway A\napplies SA2 (ESP)", "blue"); box(ax, 5.7, 1.8, 1.5, .8, "Gateway B\nSA2 lookup, ICV,\nreplay, decap", "blue"); box(ax, 7.7, 1.8, 1.3, .8, "Host B\nverifies SA1 (AH)", "orange")
arrow(ax, 1.6, 2.2, 2.0, 2.2); arrow(ax, 3.5, 2.2, 5.7, 2.2, "ESP tunnel  (SPI_2)", color="#1B6B1B", ty=.12); arrow(ax, 7.2, 2.2, 7.7, 2.2)
ax.text(.9, 1.5, "Host A adds AH\n(SA1, SPI_1):\n45 → 69 B", ha="center", fontsize=7.2); ax.text(4.6, 1.5, "Gateway A encapsulates:  69 → 124 B", ha="center", fontsize=7.2)
ax.text(4.6, .55, "Unwrapping order is the reverse of wrapping: outer SA (ESP) first, then the inner SA (AH).  Host-to-host authenticity survives even if a gateway is compromised.", ha="center", fontsize=7.5, style="italic")
save(fig, "t3_bundle")

# ---------------------------------------------------------------- 8 PKI + S/MIME failure map
t2 = L("t2"); fig, ax = canvas(9.4, 4.8); ax.text(4.7, 4.6, "Certificate hierarchy used for S/MIME and TLS, with the six failure cases", ha="center", fontweight="bold")
box(ax, 3.6, 3.7, 2.2, .55, "Hospital Root CA\n(trust anchor, pathLen 1)", "green"); box(ax, 3.6, 2.6, 2.2, .55, "Hospital Issuing CA\n(CA:true, pathLen 0)", "green"); arrow(ax, 4.7, 3.7, 4.7, 3.15); 
box(ax, .2, 1.4, 1.6, .55, "user1 / user2\n(S/MIME + client)", "blue"); box(ax, 2.2, 1.4, 1.4, .55, "server\nhospital.test", "blue"); box(ax, 3.9, 1.4, 1.4, .55, "client1\n(mTLS)", "blue")
for x in (1.0, 2.9, 4.6): arrow(ax, 4.7, 2.6, x, 1.95)
box(ax, 6.3, 3.7, 2.1, .55, "Rogue Root CA\n(NOT trusted)", "red"); box(ax, 6.3, 2.6, 2.1, .55, "rogue-user1 (claims\nuser1@hospital.test)", "red"); arrow(ax, 7.35, 3.7, 7.35, 3.15)
for x, t in [(.2, "S1 expired\nS3 wrong e-mail\nS4 revoked (CRL)"), (6.3, "S2 untrusted CA"), (2.2, "S6 intermediate\nmissing from message")]: ax.text(x, 0.65 if x < 6 else 1.9, t, fontsize=7.6, color="#A02020")
save(fig, "t2_pki")

# ---------------------------------------------------------------- 9 trust models
fig, axs = plt.subplots(1, 2, figsize=(9.6, 3.6))
for a in axs: a.axis("off")
a = axs[0]; a.set_xlim(0, 5); a.set_ylim(0, 4); a.set_title("PGP web of trust (Bob's view)", fontsize=9)
for n, (x, y), t, c in [("Carol", (.6, 3.2), "full", "#DDF0DD"), ("Dave", (1.9, 3.2), "marginal", "#FCE8CF"), ("Eve", (3.2, 3.2), "marginal", "#FCE8CF"), ("Frank", (4.4, 3.2), "untrusted", "#F8D7D7")]:
    a.add_patch(FancyBboxPatch((x - .45, y - .3), .9, .6, boxstyle="round,pad=0.02", fc=c, ec="#555")); a.text(x, y, f"{n}\n{t}", ha="center", va="center", fontsize=7.5); a.annotate("", xy=(2.5, 1.35), xytext=(x, y - .3), arrowprops=dict(arrowstyle="-|>", color="#555"))
a.add_patch(FancyBboxPatch((1.8, .8),1.4, .55, boxstyle="round,pad=0.02", fc="#DCE9F7", ec="#555")); a.text(2.5, 1.07, "Alice's key KA", ha="center", va="center", fontsize=8)
a.text(2.5, .35, "full=1 (Carol) → VALID.  Also marginal=2 → VALID.", ha="center", fontsize=7.5)
a = axs[1]; a.set_xlim(0, 5); a.set_ylim(0, 4); a.set_title("S/MIME hierarchical CA", fontsize=9)
for t, y, c in [("Trusted root (anchor)", 3.3, "#DDF0DD"), ("Intermediate CA (pathLen 0)", 2.3, "#FCE8CF"), ("Signer certificate", 1.3, "#DCE9F7")]:
    a.add_patch(FancyBboxPatch((1.1, y - .3), 2.8, .6, boxstyle="round,pad=0.02", fc=c, ec="#555")); a.text(2.5, y, t, ha="center", va="center", fontsize=8)
a.annotate("", xy=(2.5, 2.6), xytext=(2.5, 3.0), arrowprops=dict(arrowstyle="<|-")); a.annotate("", xy=(2.5, 1.6), xytext=(2.5, 2.0), arrowprops=dict(arrowstyle="<|-")); a.text(2.5, .45, "one anchor decision; every signer\ninherits trust through the chain", ha="center", fontsize=7.5)
save(fig, "p5_trust")

# ---------------------------------------------------------------- 10 TLS handshake
fig, ax = canvas(9.4, 5.2); ax.text(4.7, 5.0, "TLS 1.3 handshake with mutual authentication (observed in Task 4.2)", ha="center", fontweight="bold")
for x, n in [(1.4, "Client (lab)"), (8.0, "Server hospital.test")]: box(ax, x - .9, 4.35, 1.8, .45, n, "blue", bold=True); ax.plot([x, x], [.4, 4.35], color="#888")
seq = [(4.0, "ClientHello: versions, ciphers, key_share (X25519), SNI = hospital.test  →", 1, "#333"), (3.55, "←  ServerHello: chosen TLS_AES_256_GCM_SHA384, key_share", -1, "#333"),
       (3.1, "←  {EncryptedExtensions, CertificateRequest}   ← ENCRYPTED from here (handshake keys)", -1, "#1B6B1B"), (2.65, "←  {Certificate chain: server, Issuing CA}  {CertificateVerify}  {Finished}", -1, "#1B6B1B"),
       (2.2, "{Certificate: client1 chain}  {CertificateVerify}  {Finished}  →", 1, "#1B6B1B"), (1.5, "[Application data]  GET /records/1001  →", 1, "#A05A00"), (1.05, "←  [Application data]  200 OK + security headers", -1, "#A05A00")]
for y, t, d, c in seq: arrow(ax, 1.4 if d > 0 else 8.0, y, 8.0 if d > 0 else 1.4, y, color=c); ax.text(4.7, y + .05, t, ha="center", fontsize=7, color=c)
ax.add_patch(Rectangle((.1, 3.3), 9.2, 0.0, fc="none")); ax.text(4.7, .5, "{ } = encrypted with handshake traffic keys    [ ] = encrypted with application traffic keys", ha="center", fontsize=7.5, style="italic")
save(fig, "t4_tls")

# ---------------------------------------------------------------- 11 DMARC outcome matrix
t5 = L("t5"); ms = t5["messages"]; fig, ax = plt.subplots(figsize=(7.6, 3.5)); cols = ["spf", "dkim", "dmarc"]; ax.set_xlim(0, 5.4); ax.set_ylim(0, len(ms) + 1); ax.axis("off")
for j, c in enumerate(["SPF", "DKIM", "DMARC", "action"]): ax.text(1.4 + j * 0.95, len(ms) + .4, c, ha="center", fontweight="bold", fontsize=8.5)
for i, m in enumerate(ms):
    y = len(ms) - i - .6; ax.text(0, y + .15, m["id"], fontsize=8.5, fontweight="bold")
    for j, c in enumerate(cols + ["action"]):
        v = m["actual"][c]; col = {"pass": "#9FD09F", "fail": "#F0A0A0", "none": "#DDD", "deliver": "#9FD09F", "reject": "#F0A0A0"}.get(v, "#FFF"); ax.add_patch(Rectangle((1.0 + j * 0.95, y), .9, .5, fc=col, ec="#777")); ax.text(1.45 + j * .95, y + .25, v, ha="center", va="center", fontsize=7.5)
ax.set_title("Outcome matrix (all eight predictions matched)", fontsize=9)
save(fig, "t5_matrix")

# ---------------------------------------------------------------- 12 Hospital architecture (Part I Task 6)
fig, ax = canvas(9.6, 4.9); ax.text(4.8, 4.7, "Chosen design: one mechanism per need, chosen by what each must prove", ha="center", fontweight="bold")
box(ax, .15, 2.5, 1.7, 1.2, "Branch hospitals\n(3 sites)", "orange", bold=True); box(ax, 3.4, 2.5, 1.7, 1.2, "Central laboratory", "orange", bold=True); box(ax, 7.0, 3.3, 1.9, .9, "Doctor\n(Dr. Rao) mailbox", "orange"); box(ax, 7.0, 1.5, 1.9, .9, "Patient\nbrowser", "orange")
arrow(ax, 1.85, 3.1, 3.4, 3.1, "Need 1: IPsec ESP\ntunnel (IKE+certs)", color="#1B6B1B", ty=.12, fs=7); arrow(ax, 5.1, 3.9, 7.0, 3.8, "Need 2: S/MIME\nsign-then-encrypt", color="#1F3A5F", ty=.12, fs=7)
arrow(ax, 7.0, 1.95, 5.1, 2.7, "Need 3: TLS 1.3\n(booking service)", color="#A05A00", ty=-.6, fs=7)
box(ax, 1.4, .1, 6.8, .6, "Internal CA hierarchy: root (offline) → issuing CA → gateway, lab and doctor certificates + CRL/OCSP", "green", fs=7.5)
save(fig, "p6_arch")

# ---------------------------------------------------------------- 13 key-state machine (T6.2)
fig, ax = canvas(9.4, 3.7); ax.text(4.7, 3.5, "Recipient key-state machine (fail-closed: only ACTIVE may be wrapped for)", ha="center", fontweight="bold")
for x, y, t, c in [(.3, 1.9, "NEW /\nUNTRUSTED", "red"), (2.5, 1.9, "ACTIVE\n(in date, trust ≥ marginal)", "green"), (5.2, 1.9, "EXPIRED", "red"), (7.5, 1.9, "REVOKED\n(terminal)", "red"), (2.5, .4, "SUPERSEDED by newer\nACTIVE key (rollover)", "orange")]:
    box(ax, x, y, 1.9 if c != "green" else 2.1, .85, t, c, fs=8)
arrow(ax, 2.2, 2.32, 2.5, 2.32, "verify\nfingerprint", fs=6.5, ty=.1); arrow(ax, 4.6, 2.32, 5.2, 2.32, "now > notAfter", fs=6.5, ty=.1); arrow(ax, 7.1, 2.32, 7.5, 2.32)
arrow(ax, 3.5, 1.9, 3.5, 1.25, "new key\nissued", fs=6.5, ty=-.05); ax.text(8.4, 1.55, "revocation event\n(from ANY state)", fontsize=7, ha="center", color="#A02020")
ax.text(4.7, .1, "MISSING (no record) is a fifth blocking outcome.  Allowed: ACTIVE only.  Blocked: UNTRUSTED, NOT_YET_VALID, EXPIRED, REVOKED, MISSING.", ha="center", fontsize=7.5, style="italic")
save(fig, "t6_states")

# ---------------------------------------------------------------- 14 T6 growth plot
t6 = L("t6"); g = t6["t65"]; gn = t6["t65_noindex"]; gc = t6["t65_concat"]; fig, axs = plt.subplots(1, 2, figsize=(9.2, 3.5))
ns = [x["n"] for x in g]
axs[0].loglog(ns, [x["size"] for x in g], "o-", color="#1F3A5F", label="hybrid (measured)"); axs[0].loglog(ns, [x["naive_bytes"] for x in g], "s--", color="#A02020", label="encrypt whole message per recipient"); axs[0].set_xlabel("recipients"); axs[0].set_ylabel("message bytes"); axs[0].legend(fontsize=7.5); axs[0].set_title("Message size (4 KB body)", fontsize=9)
axs[1].loglog(ns, [x["time_ms"] for x in gn], "s--", color="#A02020", label="v1: no index + concat"); axs[1].loglog(ns, [x["time_ms"] for x in gc], "^--", color="#D08A00", label="v2: index, concat"); axs[1].loglog(ns, [x["time_ms"] for x in g], "o-", color="#1F3A5F", label="v3: index + join (final)")
axs[1].set_xlabel("recipients"); axs[1].set_ylabel("time (ms)"); axs[1].legend(fontsize=7.5); axs[1].set_title("Execution time — an implementation defect found by measurement", fontsize=8.5)
save(fig, "t6_growth")

# ---------------------------------------------------------------- 15 spam sweep + scaling
sp = t5["spam"]; fig, axs = plt.subplots(1, 2, figsize=(9.4, 3.2)); th = [x["threshold"] for x in sp["sweep"]]
axs[0].plot(th, [x["fp"] for x in sp["sweep"]], "o-", color="#1F3A5F", label="FP (with auth)"); axs[0].plot(th, [x["fn"] for x in sp["sweep"]], "s-", color="#A02020", label="FN (with auth)")
axs[0].plot(th, [x["fp"] for x in sp["content_only_sweep"]], "o--", color="#7FA0CC", label="FP (content only)"); axs[0].plot(th, [x["fn"] for x in sp["content_only_sweep"]], "s--", color="#E09090", label="FN (content only)")
axs[0].axvline(3, color="#999", ls=":"); axs[0].set_xlabel("threshold"); axs[0].set_ylabel("messages (of 6 per class)"); axs[0].legend(fontsize=7); axs[0].set_title("Spam classifier: threshold sweep", fontsize=9)
sc = t2["scaling"]; axs[1].bar([f"{s['contacts']} trusted\n{s['signers']} signers" for s in sc], [s["pgp_valid_fraction"] * 100 for s in sc], color="#9DB9DD", label="PGP (simulated)"); axs[1].axhline(100, color="#1B6B1B", ls="--", label="S/MIME (1 trust anchor)")
axs[1].set_ylabel("% of stranger keys that validate"); axs[1].set_ylim(0, 110); axs[1].legend(fontsize=7.5, loc="center left"); axs[1].set_title("Task 2.4 — N = 5,000 users", fontsize=9)
save(fig, "t5_t2_plots")
print(sorted(os.listdir(F)))
