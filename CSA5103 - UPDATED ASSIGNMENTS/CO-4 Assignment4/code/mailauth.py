#!/usr/bin/env python3
"""mailauth.py - own implementation of SPF, DKIM (rsa-sha256, relaxed/relaxed) and DMARC evaluation against a SIMULATED DNS zone file.
Every function returns (result, evidence-list) - never just pass/fail."""
import re, base64, hashlib, ipaddress, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


class Zone:
    def __init__(self, records): self.r = records; self.queries = 0
    def txt(self, name):
        self.queries += 1; return self.r.get(name.lower())


def domain_of(addr): return addr.rsplit("@", 1)[-1].strip(" <>").lower()
def org_domain(d): return ".".join(d.split(".")[-2:])                   # simplified organisational-domain rule for the test TLD (.test/.example)


# ------------------------------------------------------------------ SPF  (authenticates: envelope sender domain + connecting IP)
def spf_check(ip, mail_from, zone, depth=0, domain=None, ev=None):
    ev = [] if ev is None else ev; domain = domain or domain_of(mail_from)
    if depth > 10: ev.append("DNS-lookup limit (10) exceeded"); return "permerror", ev
    rec = zone.txt(domain)
    if rec is None or not rec.startswith("v=spf1"): ev.append(f"no SPF record published for {domain}"); return "none", ev
    ev.append(f"SPF record of {domain}: {rec}")
    for term in rec.split()[1:]:
        q = "+"
        if term[0] in "+-~?": q, term = term[0], term[1:]
        hit = False
        if term.startswith("ip4:"):
            net = ipaddress.ip_network(term[4:], strict=False); hit = ipaddress.ip_address(ip) in net; ev.append(f"mechanism {term}: {ip} {'inside' if hit else 'outside'} {net}")
        elif term.startswith("include:"):
            sub, _ = spf_check(ip, mail_from, zone, depth + 1, term[8:], ev); hit = (sub == "pass"); ev.append(f"mechanism {term}: nested result {sub}")
        elif term == "all": hit = True; ev.append("mechanism all: matches everything not matched earlier")
        if hit:
            res = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[q]; ev.append(f"=> qualifier '{q}' => {res}"); return res, ev
    ev.append("end of record reached without a match -> neutral"); return "neutral", ev


# ------------------------------------------------------------------ DKIM  (authenticates: the d= domain's key over selected headers + body hash)
def canon_header(name, value): return name.lower().strip() + ":" + re.sub(r"[ \t]+", " ", re.sub(r"\r?\n[ \t]+", " ", value)).strip() + "\r\n"
def canon_body(body):
    lines = [re.sub(r"[ \t]+", " ", l).rstrip(" \t") for l in body.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "": lines.pop()
    return ("\r\n".join(lines) + "\r\n") if lines else ""
def body_hash(body): return base64.b64encode(hashlib.sha256(canon_body(body).encode()).digest()).decode()
def dkim_input(headers, signed_names, sig_value_no_b):
    out = ""; used = list(headers)
    for n in signed_names:
        for i in range(len(used) - 1, -1, -1):                              # bottom-most instance first, as in RFC 6376
            if used[i][0].lower() == n.lower(): out += canon_header(*used[i]); used.pop(i); break
    return out + canon_header("DKIM-Signature", sig_value_no_b).rstrip("\r\n")


def dkim_sign(headers, body, key, domain, selector, signed=("from", "to", "subject", "date")):
    bh = body_hash(body); tag = f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; h={':'.join(signed)}; bh={bh}; b="
    sig = key.sign(dkim_input(headers, signed, tag).encode(), padding.PKCS1v15(), hashes.SHA256())
    return [("DKIM-Signature", tag + base64.b64encode(sig).decode())] + list(headers)


def dkim_verify(headers, body, zone):
    ev = []; sigs = [h for h in headers if h[0].lower() == "dkim-signature"]
    if not sigs: ev.append("no DKIM-Signature header"); return "none", None, ev
    val = sigs[0][1]; tags = dict(t.strip().split("=", 1) for t in val.split(";") if "=" in t); d, s = tags["d"], tags["s"]
    ev.append(f"signature: d={d} s={s} a={tags['a']} c={tags['c']} signed headers={tags['h']}")
    rec = zone.txt(f"{s}._domainkey.{d}")
    if rec is None: ev.append(f"no DNS key at {s}._domainkey.{d}"); return "permerror", d, ev
    ev.append(f"DNS key found at {s}._domainkey.{d}")
    bh_now = body_hash(body); ev.append(f"body hash: signed {tags['bh'][:16]}... computed {bh_now[:16]}... -> {'match' if bh_now == tags['bh'] else 'MISMATCH (body changed after signing)'}")
    if bh_now != tags["bh"]: return "fail", d, ev
    pub = serialization.load_der_public_key(base64.b64decode(dict(x.strip().split("=", 1) for x in rec.split(";") if "=" in x)["p"]))
    others = [h for h in headers if h[0].lower() != "dkim-signature"]; tag_no_b = val[:val.rindex("b=") + 2]
    try: pub.verify(base64.b64decode(tags["b"]), dkim_input(others, tags["h"].split(":"), tag_no_b).encode(), padding.PKCS1v15(), hashes.SHA256()); ev.append("RSA signature over the canonicalised signed headers: valid"); return "pass", d, ev
    except InvalidSignature: ev.append("RSA signature over the signed headers: INVALID (a signed header changed)"); return "fail", d, ev


# ------------------------------------------------------------------ DMARC  (authenticates: the visible From domain, by ALIGNMENT)
def dmarc_eval(from_domain, spf_res, spf_domain, dkim_res, dkim_domain, zone):
    ev = []; rec = zone.txt("_dmarc." + from_domain) or zone.txt("_dmarc." + org_domain(from_domain))
    if rec is None: ev.append(f"no DMARC record for {from_domain}"); return "none", "none", ev
    tags = dict(t.strip().split("=", 1) for t in rec.split(";") if "=" in t); p = tags.get("p", "none"); adkim = tags.get("adkim", "r"); aspf = tags.get("aspf", "r"); ev.append(f"DMARC record: {rec}")
    al = lambda a, b, mode: (a == b) if mode == "s" else (org_domain(a) == org_domain(b))
    spf_al = spf_res == "pass" and al(spf_domain, from_domain, aspf); dkim_al = dkim_res == "pass" and dkim_domain and al(dkim_domain, from_domain, adkim)
    ev.append(f"SPF: result={spf_res}, envelope domain={spf_domain}, visible From={from_domain}, mode={aspf} -> {'ALIGNED' if spf_al else 'not aligned/not pass'}")
    ev.append(f"DKIM: result={dkim_res}, d={dkim_domain}, visible From={from_domain}, mode={adkim} -> {'ALIGNED' if dkim_al else 'not aligned/not pass'}")
    ok = spf_al or dkim_al; ev.append(f"DMARC passes if SPF-aligned OR DKIM-aligned: {ok}")
    return ("pass" if ok else "fail"), ("deliver" if ok else {"none": "deliver (monitor only)", "quarantine": "quarantine", "reject": "reject"}[p]), ev


def new_rsa(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def dns_key(k): return "v=DKIM1; k=rsa; p=" + base64.b64encode(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
