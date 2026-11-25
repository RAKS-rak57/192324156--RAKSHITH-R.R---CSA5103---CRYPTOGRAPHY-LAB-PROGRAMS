#!/usr/bin/env python3
"""Part II Task 5 (+ Part I Task 5 email-header / spam coverage) - experiments on a simulated DNS zone."""
import os, sys, json, re
sys.path.insert(0, os.path.dirname(__file__))
import mailauth as M

R = os.path.join(os.path.dirname(__file__), "..", "results"); W = os.path.join(os.path.dirname(__file__), "..", "work"); os.makedirs(R, exist_ok=True)
hk, ek, lk = M.new_rsa(), M.new_rsa(), M.new_rsa()                  # TEST DKIM keys for hospital.test, evil.test, lists.example (generated at run time)
zone_records = {
    "hospital.test": "v=spf1 ip4:192.0.2.10 include:_spf.mailer.test -all",
    "_spf.mailer.test": "v=spf1 ip4:203.0.113.0/26 -all",
    "lists.example": "v=spf1 ip4:198.51.100.25 -all",
    "evil.test": "v=spf1 ip4:203.0.113.99 -all",
    "fwd.example": "v=spf1 ip4:198.51.100.77 -all",
    "selector1._domainkey.hospital.test": M.dns_key(hk),
    "selector1._domainkey.evil.test": M.dns_key(ek),
    "_dmarc.hospital.test": "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc@hospital.test",
}
json.dump(zone_records, open(W + "/zone.json", "w"), indent=1)       # the simulated DNS zone file (public data only)
zone = M.Zone(json.load(open(W + "/zone.json")))
BODY = "Dear Dr. Rao,\r\nThe CBC report for patient 1001 is attached.\r\nRegards,\r\nCentral Laboratory\r\n"
base_headers = [("From", "Central Lab <lab@hospital.test>"), ("To", "dr.rao@clinic.example"), ("Subject", "CBC report 1001"), ("Date", "Tue, 17 Nov 2026 09:00:00 +0530"), ("Message-ID", "<a1@hospital.test>")]
signed_legit = M.dkim_sign(base_headers, BODY, hk, "hospital.test", "selector1")

msgs = [
 dict(id="M1", title="Legitimate message from the hospital mail server", ip="192.0.2.10", mail_from="bounce@hospital.test", headers=signed_legit, body=BODY,
      predict=dict(spf="pass", dkim="pass", dmarc="pass", action="deliver")),
 dict(id="M2", title="Spoofed message: attacker's server claims hospital.test, no DKIM", ip="203.0.113.99", mail_from="lab@hospital.test", headers=base_headers, body=BODY,
      predict=dict(spf="fail", dkim="none", dmarc="fail", action="reject")),
 dict(id="M3", title="Mailing list adds footer and subject tag after DKIM signing", ip="198.51.100.25", mail_from="owner-list@lists.example",
      headers=[(n, ("[Clinic-List] " + v) if n == "Subject" else v) for n, v in signed_legit], body=BODY + "\r\n-- \r\nYou are subscribed to Clinic-List\r\n",
      predict=dict(spf="pass", dkim="fail", dmarc="fail", action="reject")),
 dict(id="M3b", title="Mailing list that only ADDS an unsigned List-Id header (body and signed headers untouched)", ip="198.51.100.25", mail_from="owner-list@lists.example",
      headers=signed_legit + [("List-Id", "<clinic-list.lists.example>")], body=BODY, predict=dict(spf="pass", dkim="pass", dmarc="pass", action="deliver")),
 dict(id="M4", title="Attacker passes SPF and DKIM for evil.test but shows From: lab@hospital.test", ip="203.0.113.99", mail_from="x@evil.test",
      headers=M.dkim_sign(base_headers, BODY, ek, "evil.test", "selector1"), body=BODY, predict=dict(spf="pass", dkim="pass", dmarc="fail", action="reject")),
 dict(id="M5", title="Legitimate message forwarded unchanged by fwd.example (envelope sender kept)", ip="198.51.100.77", mail_from="bounce@hospital.test", headers=signed_legit, body=BODY,
      predict=dict(spf="fail", dkim="pass", dmarc="pass", action="deliver")),
 dict(id="M6", title="Newsletter service (authorised via include:) signing with the hospital's delegated key", ip="203.0.113.50", mail_from="bounce@hospital.test", headers=signed_legit, body=BODY,
      predict=dict(spf="pass", dkim="pass", dmarc="pass", action="deliver")),
 dict(id="M7", title="Content modified in transit by an on-path attacker; sent from the authorised server (SPF aligned)", ip="192.0.2.10", mail_from="bounce@hospital.test", headers=signed_legit,
      body=BODY.replace("1001", "1002"), predict=dict(spf="pass", dkim="fail", dmarc="pass", action="deliver")),
]
out = []
for m in msgs:
    spf_res, spf_ev = M.spf_check(m["ip"], m["mail_from"], zone)
    dk_res, dk_dom, dk_ev = M.dkim_verify(m["headers"], m["body"], zone)
    frm = next(v for n, v in m["headers"] if n == "From"); fd = M.domain_of(re.search(r"<(.+)>", frm).group(1))
    dm_res, action, dm_ev = M.dmarc_eval(fd, spf_res, M.domain_of(m["mail_from"]), dk_res, dk_dom, zone)
    actual = dict(spf=spf_res, dkim=dk_res, dmarc=dm_res, action=action)
    out.append(dict(id=m["id"], title=m["title"], ip=m["ip"], mail_from=m["mail_from"], from_domain=fd, predicted=m["predict"], actual=actual, match=all(m["predict"][k] == actual[k] for k in m["predict"]),
                    spf_evidence=spf_ev, dkim_evidence=dk_ev, dmarc_evidence=dm_ev))
res = dict(zone=zone_records, messages=out)
# deployment experiment: third-party sender WITHOUT include: in SPF (large organisation pitfall)
z2 = M.Zone({**zone_records, "hospital.test": "v=spf1 ip4:192.0.2.10 -all"})
s, e = M.spf_check("203.0.113.50", "bounce@hospital.test", z2); d, dd, de = M.dkim_verify(signed_legit, BODY, z2); dm = M.dmarc_eval("hospital.test", s, "hospital.test", d, dd, z2)
res["no_include"] = dict(spf=s, dkim=d, dmarc=dm[0], action=dm[1])

# ------------------------------------------------------------------ header analysis (Part I coverage) on one raw phishing message
raw = """Return-Path: <bounce@mail-relay.evil.test>
Received: from mx.clinic.example (mx.clinic.example [198.51.100.2]) by inbox.clinic.example with ESMTPS; Tue, 17 Nov 2026 09:05:12 +0530
Received: from unknown (HELO mailer.evil.test) ([203.0.113.99]) by mx.clinic.example with SMTP; Tue, 17 Nov 2026 09:05:10 +0530
Authentication-Results: mx.clinic.example; spf=fail smtp.mailfrom=mail-relay.evil.test; dkim=none; dmarc=fail header.from=hospital.test
From: "Central Lab" <lab@hospital.test>
To: dr.rao@clinic.example
Reply-To: <payments@hospital-billing.example>
Subject: URGENT: verify your password immediately
Date: Tue, 17 Nov 2026 03:35:01 +0000
Message-ID: <9f3a@mailer.evil.test>
"""
hdr = {}; received = []
for l in raw.strip().splitlines():
    k, v = l.split(":", 1)
    if k == "Received": received.append(v.strip())
    else: hdr[k] = v.strip()
dom = lambda s: M.domain_of(re.search(r"<(.+?)>", s).group(1)) if "<" in s else M.domain_of(s)
findings = [("From (visible identity)", hdr["From"], "what the user sees - freely forgeable"),
            ("Return-Path (envelope sender)", hdr["Return-Path"], f"domain {dom(hdr['Return-Path'])} differs from From domain {dom(hdr['From'])}: SPF was evaluated on THIS domain"),
            ("Reply-To", hdr["Reply-To"], f"domain {dom(hdr['Reply-To'])} differs from From domain: replies go elsewhere"),
            ("Message-ID", hdr["Message-ID"], f"generated by {M.domain_of(hdr['Message-ID'].strip('<>'))}, not by hospital.test"),
            ("Date", hdr["Date"], "03:35 UTC = 09:05 +0530: consistent with the first Received time (no clock anomaly)"),
            ("Authentication-Results", hdr["Authentication-Results"], "receiving MTA's own verdict: spf=fail, dkim=none, dmarc=fail"),
            ("Received #2 (bottom = first hop)", received[1], "true origin: IP 203.0.113.99 / HELO mailer.evil.test - the delivery path"),
            ("Received #1 (top = last hop)", received[0], "added by our own MX: the only hop we can trust")]
res["header_analysis"] = dict(raw=raw.strip().splitlines(), findings=findings)

# ------------------------------------------------------------------ score-based spam / phishing classifier
URG = ["urgent", "verify", "password", "immediately", "suspended", "wire", "gift card", "click here", "act now", "confirm your account"]
def features(m, use_auth=True):
    f = {}; s = 0
    if m["reply_to"] and m["reply_to"] != m["from"]: f["F1 Reply-To domain differs from From"] = 2
    if m["return_path"] != m["from"]: f["F2 Return-Path domain differs from From"] = 1
    k = sum(1 for w in URG if w in (m["subject"] + " " + m["body"]).lower()); 
    if k: f[f"F3 urgency/credential words x{k}"] = min(k, 3)
    if m["link_mismatch"]: f["F4 link text/IP differs from target"] = 2
    letters = [c for c in m["subject"] if c.isalpha()]
    if letters and sum(c.isupper() for c in letters) / len(letters) > .6: f["F5 subject mostly capitals"] = 1
    if m["msgid"] != m["from"]: f["F6 Message-ID domain differs from From"] = 1
    if not m["date_ok"]: f["F7 Date missing/implausible"] = 1
    if use_auth:
        a = m["auth"]
        if a["spf"] == "fail": f["A1 SPF fail"] = 2
        elif a["spf"] == "softfail": f["A1 SPF softfail"] = 1
        if a["dkim"] in ("fail", "none"): f["A2 DKIM " + a["dkim"]] = 1
        if a["dmarc"] == "fail": f["A3 DMARC fail"] = 2
        if a["dmarc"] == "pass": f["A4 DMARC pass (reduces score)"] = -2
    return f
def mk(id, label, desc, frm, subject, body, rp=None, ret=None, mid=None, link=False, date_ok=True, spf="pass", dkim="pass", dmarc="pass"):
    return dict(id=id, label=label, desc=desc, **{"from": frm}, subject=subject, body=body, reply_to=rp, return_path=ret or frm, msgid=mid or frm, link_mismatch=link, date_ok=date_ok, auth=dict(spf=spf, dkim=dkim, dmarc=dmarc))
corpus = [
 mk("H1", "ham", "Normal lab report from the hospital server", "hospital.test", "CBC report 1001", "The report is attached."),
 mk("H2", "ham", "Newsletter sent by an authorised third-party service", "hospital.test", "Monthly health bulletin", "Read our newsletter.", ret="mailer.test", mid="mailer.test", spf="pass", dkim="pass", dmarc="pass"),
 mk("H3", "ham", "Legitimate message relayed by a mailing list that rewrote the body", "hospital.test", "[Clinic-List] CBC meeting", "Agenda below.", rp="lists.example", ret="lists.example", mid="lists.example", spf="pass", dkim="fail", dmarc="fail"),
 mk("H4", "ham", "Legitimate message forwarded unchanged (SPF breaks, DKIM holds)", "hospital.test", "Ward rota", "Rota attached.", spf="fail", dkim="pass", dmarc="pass"),
 mk("H5", "ham", "Genuine urgent critical-value alert from the lab", "hospital.test", "URGENT critical potassium value", "Call the ward immediately.", spf="pass", dkim="pass", dmarc="pass"),
 mk("H6", "ham", "Appointment reminder with a tracking link (display text differs from target)", "clinic.example", "Your appointment tomorrow", "Click here to confirm.", link=True, spf="pass", dkim="pass", dmarc="pass"),
 mk("S1", "spam", "Classic credential phish: spoofed From, IP-address link", "hospital.test", "URGENT: verify your password immediately", "Click here to confirm your account.", ret="evil.test", mid="evil.test", link=True, spf="fail", dkim="none", dmarc="fail"),
 mk("S2", "spam", "Business e-mail compromise: spoofed CFO asks for a wire", "hospital.test", "Payment needed", "Please wire the amount today, reply to me.", rp="hospital-billing.example", ret="evil.test", mid="evil.test", spf="fail", dkim="none", dmarc="fail"),
 mk("S3", "spam", "Look-alike domain (hospita1.test) with its own valid SPF/DKIM/DMARC", "hospita1.test", "Verify your password", "Your account is suspended. Click here immediately.", link=True, spf="pass", dkim="pass", dmarc="pass"),
 mk("S4", "spam", "Phish sent from a COMPROMISED genuine hospital mailbox (all authentication passes)", "hospital.test", "Shared document", "Please review the document I shared with you.", spf="pass", dkim="pass", dmarc="pass"),
 mk("S5", "spam", "Bulk advert: capitals, urgency, softfail", "promo.example", "ACT NOW!!! CHEAP MEDS", "Act now, urgent offer, click here.", ret="promo.example", mid="bulk.example", date_ok=False, spf="softfail", dkim="none", dmarc="none"),
 mk("S6", "spam", "Gift-card scam, forged From, mismatching Message-ID", "hospital.test", "Quick favour", "Buy a gift card immediately and send the code.", rp="x@free-mail.example", ret="free-mail.example", mid="free-mail.example", spf="fail", dkim="none", dmarc="fail"),
]
def evaluate(th, use_auth=True):
    tp = fp = fn = tn = 0; rows = []
    for m in corpus:
        f = features(m, use_auth); sc = sum(f.values()); pred = "spam" if sc >= th else "ham"
        tp += (pred == "spam" and m["label"] == "spam"); fp += (pred == "spam" and m["label"] == "ham"); fn += (pred == "ham" and m["label"] == "spam"); tn += (pred == "ham" and m["label"] == "ham")
        rows.append(dict(id=m["id"], label=m["label"], desc=m["desc"], score=sc, pred=pred, features=f, outcome=("TP" if pred == "spam" and m["label"] == "spam" else "FP" if pred == "spam" else "FN" if m["label"] == "spam" else "TN")))
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn); return dict(threshold=th, tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, rows=rows)
res["spam"] = dict(main=evaluate(3), sweep=[{k: v for k, v in evaluate(t).items() if k != "rows"} for t in range(2, 9)], content_only=evaluate(3, use_auth=False))
res["spam"]["content_only_sweep"] = [{k: v for k, v in evaluate(t, False).items() if k != "rows"} for t in range(2, 9)]
json.dump(res, open(R + "/t5.json", "w"), indent=1)
for m in out: print(m["id"], m["actual"], "match" if m["match"] else "MISMATCH", m["predicted"])
print("no include:", res["no_include"])
e = res["spam"]["main"]; print({k: e[k] for k in ("threshold", "tp", "fp", "fn", "tn", "precision", "recall")})
for r in e["rows"]: print(r["id"], r["label"], r["score"], r["outcome"])
print([(x["threshold"], x["fp"], x["fn"]) for x in res["spam"]["sweep"]]); print("content only", [(x["threshold"], x["fp"], x["fn"]) for x in res["spam"]["content_only_sweep"]])
