from rb_lib import *


def build():
    # ============================================================= TASK 4
    H2("TASK 4 – PSEUDOCODE FORENSICS: FIND, EXPLAIN AND REPAIR A SECURITY DEFECT (7 marks)", True)
    CODE("""ALGORITHM AcceptSignedMessage(Msg, Sig, SignerCert, TrustedRoots, Now)
 BEGIN
   digest <- HASH(Msg)
   IF VERIFY(SignerCert.publicKey, digest, Sig) = TRUE THEN
   IF SignerCert.notBefore <= Now AND Now <= SignerCert.notAfter THEN
   RETURN ACCEPT
   END IF
   END IF
   RETURN REJECT
 END""", title="Given pseudocode (abridged to its logic)")
    H3("Task 4.1 – Locate the defect (2 marks)")
    P("**The incomplete decision is the final one:** `IF SignerCert.notBefore <= Now AND Now <= SignerCert.notAfter THEN RETURN ACCEPT`. At that point the algorithm has established exactly two facts – (1) whoever produced `Sig` holds the private key that matches the public key inside `SignerCert`, and (2) that certificate is inside its validity period – and then accepts. Evidence of the defect is visible in the signature of the algorithm itself: **`TrustedRoots` is an input that is never used**.")
    P("**Why these two facts are not sufficient.** `SignerCert` arrives __with the message__, so it is chosen by whoever sent the message; an attacker can generate a key pair, wrap the public key in a self-made certificate carrying any name and any dates, and sign with the matching private key. Fact (1) then holds trivially. A certificate is a __claim__ (“this key belongs to this address”) that is worth something only if a party the verifier already trusts has vouched for it. The missing decisions are therefore: **(a)** does a chain of valid issuer signatures lead from `SignerCert` to a certificate in `TrustedRoots`? **(b)** are the issuers in that chain actually allowed to issue certificates (basicConstraints CA = true, path-length, key usage keyCertSign)? **(c)** is the certificate allowed to sign mail (keyUsage digitalSignature, extended key usage emailProtection)? **(d)** does the certificate’s subject (email address) equal the address the message claims to be from? **(e)** has the certificate – or any issuer – been revoked? **(f)** is every certificate in the chain, not only the leaf, inside its validity period?")
    H3("Task 4.2 – A failing input and its trace (2 marks)")
    P("Two student-designed scenarios; the defective algorithm returns ACCEPT in both, although the message must not be trusted.")
    CAPT("t4fail", "Failing inputs for the original algorithm")
    TBL(["Item", "Scenario A – attacker-made self-signed certificate", "Scenario B – genuine certificate of a different person"], [
        ["Msg", "“Please transfer 50,000 to account 7781 – CFO”", "same text"],
        ["Claimed sender (From)", "cfo@hospital.test", "cfo@hospital.test"],
        ["SignerCert", "Created by Mallory: subject `cfo@hospital.test`, issuer = subject (**self-signed**), notBefore = Now − 1 day, notAfter = Now + 1 year", "Issued by Hospital Issuing CA to **nurse@hospital.test** (a real employee, Mallory has stolen or been given that account’s key), validity current"],
        ["TrustedRoots", "{ Hospital Root CA }", "{ Hospital Root CA }"],
        ["Sig", "SIGN(Mallory private key, HASH(Msg))", "SIGN(nurse private key, HASH(Msg))"],
        ["Trace", "1. `digest <- HASH(Msg)`.\n2. `VERIFY(Mallory public key, digest, Sig) = TRUE` (she signed it).\n3. `notBefore <= Now <= notAfter` → TRUE.\n4. **`RETURN ACCEPT`** – first incorrect decision: the certificate was never related to `TrustedRoots`.", "1. `digest <- HASH(Msg)`.\n2. `VERIFY` → TRUE.\n3. validity → TRUE.\n4. **`RETURN ACCEPT`** – first incorrect decision: the certificate chain is fine, but its subject (nurse@…) was never compared with the claimed sender (cfo@…)."],
        ["Why the result is wrong", "No trusted party vouches for Mallory’s key.", "The signature is genuine but proves the __nurse__ signed, not the CFO."]], [1.1, 2.75, 2.75], 8.2, firstbold=True)
    P("__Cross-check (Part II Task 2):__ the same two situations were tried against OpenSSL’s CMS verifier – a rogue-CA certificate claiming user1’s address (S2) fails with “unable to get local issuer certificate”, and a genuine certificate used with the wrong address (S3) fails with “email address mismatch”.", 9)
    H3("Task 4.3 – Minimal repair (2 marks)")
    P("Only the final decision is corrected; the digest, signature and date tests are kept as they are. The new checks are placed in one reusable algorithm, `ValidateCertificate`, which the other algorithms of this report also call. New or changed lines are marked `// NEW`.")
    CODE("""ALGORITHM AcceptSignedMessage(Msg, Sig, SignerCert, TrustedRoots, Now, SenderAddr, Intermediates, CRLs)      // NEW inputs: SenderAddr, Intermediates, CRLs
 OUTPUT: ACCEPT, or (REJECT, reason)                                                                          // NEW: a reason on every failure
 BEGIN
   digest <- HASH(Msg)
   IF VERIFY(SignerCert.publicKey, digest, Sig) = TRUE THEN
     IF SignerCert.notBefore <= Now AND Now <= SignerCert.notAfter THEN
        r <- ValidateCertificate(SignerCert, SenderAddr, "digitalSignature", TrustedRoots, Intermediates, CRLs, Now)   // NEW
        IF r = OK THEN RETURN ACCEPT                                                                           // NEW
        ELSE RETURN (REJECT, r) END IF                                                                         // NEW
     ELSE RETURN (REJECT, CERT_EXPIRED_OR_NOT_YET_VALID) END IF                                                // NEW reason
   ELSE RETURN (REJECT, BAD_SIGNATURE) END IF                                                                  // NEW reason
 END

ALGORITHM ValidateCertificate(Cert, ExpectedAddr, Usage, TrustedRoots, Intermediates, CRLs, Now)             // NEW
 OUTPUT: OK or a failure code
 BEGIN
   chain <- [Cert];  cur <- Cert
   WHILE cur NOT IN TrustedRoots DO                                          // (a) path construction up to a trust anchor
      issuer <- FIND(Intermediates UNION TrustedRoots, subject = cur.issuer AND keyID = cur.authorityKeyID)
      IF issuer = NULL THEN RETURN NO_PATH_TO_TRUSTED_ROOT END IF
      IF NOT VERIFY(issuer.publicKey, HASH(cur.toBeSigned), cur.signature) THEN RETURN BAD_CERT_SIGNATURE END IF
      IF issuer.basicConstraints.CA <> TRUE OR issuer.keyUsage lacks keyCertSign THEN RETURN ISSUER_NOT_A_CA END IF      // (b)
      IF issuer.pathLen is defined AND (CA certificates between issuer and Cert) > issuer.pathLen THEN RETURN PATHLEN_EXCEEDED END IF
      APPEND issuer TO chain;  cur <- issuer
      IF LENGTH(chain) > MAX_DEPTH THEN RETURN PATH_TOO_LONG END IF
   END WHILE
   FOR EACH c IN chain DO                                                    // (f) every certificate, not only the leaf
      IF NOT (c.notBefore <= Now AND Now <= c.notAfter) THEN RETURN CERT_EXPIRED_OR_NOT_YET_VALID END IF
   END FOR
   IF Usage NOT IN Cert.keyUsage OR Cert.extendedKeyUsage lacks the purpose for Usage THEN RETURN WRONG_KEY_USAGE END IF   // (c)
   IF ExpectedAddr <> NONE AND ExpectedAddr NOT IN Cert.subjectAltName.emails THEN RETURN IDENTITY_MISMATCH END IF         // (d)
   FOR EACH (c, iss) IN consecutive pairs of chain DO                        // (e) revocation, checked at every level
      crl <- FIND(CRLs, issuer = iss.subject)
      IF crl = NULL OR crl.nextUpdate < Now OR NOT VERIFY(iss.publicKey, HASH(crl.body), crl.signature) THEN RETURN REVOCATION_STATUS_UNKNOWN END IF   // fail closed
      IF c.serial IN crl.revokedSerials THEN RETURN CERT_REVOKED END IF
   END FOR
   RETURN OK
 END""")
    P("**What is returned for each failure:** `NO_PATH_TO_TRUSTED_ROOT` (untrusted issuer, or missing intermediate), `BAD_CERT_SIGNATURE`, `ISSUER_NOT_A_CA`, `PATHLEN_EXCEEDED`, `CERT_EXPIRED_OR_NOT_YET_VALID`, `WRONG_KEY_USAGE`, `IDENTITY_MISMATCH`, `CERT_REVOKED`, `REVOCATION_STATUS_UNKNOWN` – each a REJECT. A trust anchor is accepted because it is __in__ `TrustedRoots`, so its self-signature is deliberately not verified.", 9.5)
    H3("Task 4.4 – Regression check (1 mark)")
    CAPT("t4reg", "Inputs whose original result was already correct, and the repaired result")
    TBL(["Input", "Original result", "Repaired result", "Why the same"], [
        ["**R1 (main):** genuine message from lab@hospital.test; certificate issued by Hospital Issuing CA under Hospital Root CA; valid dates; not on the CRL; `SenderAddr` = lab@hospital.test", "ACCEPT (correct)", "ACCEPT", "Signature verifies; dates valid; new checks: path found (leaf → Issuing CA → Root), CA flags and pathLen OK, usage OK, address equal, CRL fresh and serial absent → `OK`."],
        ["R2: same genuine message but one character changed after signing", "REJECT (VERIFY false)", "REJECT, BAD_SIGNATURE", "The signature test is unchanged and still runs first; new checks are never reached."],
        ["R3: genuine message but certificate expired last month", "REJECT (date test)", "REJECT, CERT_EXPIRED_OR_NOT_YET_VALID", "Date test kept; the reason is now explicit."]], [2.6, 1.1, 1.4, 1.5], 8.2)
    P("__Cross-check (Part II Task 2):__ R1 corresponds to the S/MIME normal case (all eight validation steps pass), R2 to case S5 (content verify error) and R3 to case S1 (certificate has expired); in each case the OpenSSL result and the student validator agree.", 9)
    BOX("Rubric check – Task 4", ["4.1 ✔ defect identified (final decision; `TrustedRoots` unused) with six missing decisions.  4.2 ✔ two designed inputs with traces and first wrong decision.  4.3 ✔ minimal correction with trust, identity, revocation and a reason per failure.  4.4 ✔ regression table (R1–R3)."])

    # ============================================================= TASK 5
    H2("TASK 5 – SAME KEY, DIFFERENT TRUST REASONING (7 marks)", True)
    H3("Task 5.1 – Web-of-trust evaluation (3 marks)")
    CODE("""ALGORITHM KeyValidity(K, KeyRing, OwnerTrust, Now)
 INPUT:  K - the key being judged;  KeyRing;  OwnerTrust - table: introducer -> FULL | MARGINAL | UNTRUSTED;  Now
 OUTPUT: VALID, INVALID or UNKNOWN
 BEGIN
   IF K.revoked OR Now > K.expiry THEN RETURN INVALID END IF                     // the key itself is unusable
   full <- 0;  marginal <- 0;  bad <- 0;  seen <- EMPTY SET
   FOR EACH sig IN SIGNATURES_ON(K) DO                                           // 1. collect the signatures on K
      signer <- LOOKUP(KeyRing, sig.signerID)
      IF signer = NULL THEN CONTINUE END IF                                      // unknown introducer: contributes nothing
      IF signer.revoked OR Now > signer.expiry THEN CONTINUE END IF              // revoked/expired signer: ignored
      IF signer.ID IN seen THEN CONTINUE END IF                                  // each introducer counted once
      IF NOT VERIFY(signer.publicKey, HASH(K.userID || K.publicKey), sig.value) THEN        // 2. is the signature itself valid?
           bad <- bad + 1;  CONTINUE END IF
      ADD signer.ID TO seen
      t <- OwnerTrust[signer.ID]                                                 // 3. count by owner trust
      IF t = FULL THEN full <- full + 1
      ELSE IF t = MARGINAL THEN marginal <- marginal + 1 END IF                  // UNTRUSTED / unlisted count for nothing
   END FOR
   IF full >= 1 OR marginal >= 2 THEN RETURN VALID END IF                        // 4. Bob's validity rule
   IF bad > 0 AND full + marginal = 0 THEN RETURN INVALID END IF                 // only forged certifications present
   RETURN UNKNOWN                                                                // not enough trusted evidence
 END""")
    CAPT("t5wot", "The algorithm applied to Alice’s key KA (Bob’s owner-trust table) and to variations")
    TBL(["Case", "Signatures on KA", "full", "marginal", "Result", "Reasoning"], [
        ["**A (as given)**", "Carol (Full), Dave (Marg.), Eve (Marg.), Frank (Untr.) – all signatures verify", "1", "2", "**VALID**", "Frank counts for nothing. Both conditions hold independently: one full introducer, and two marginal introducers."],
        ["B", "As A, but Carol’s key is **revoked**", "0", "2", "**VALID**", "Carol skipped; Dave + Eve still satisfy ‘two marginal’."],
        ["C", "As A, but Carol revoked **and** Eve’s key expired", "0", "1", "**UNKNOWN**", "Only Dave counts: insufficient, but nothing is forged, so not INVALID."],
        ["D", "As A, but Carol’s signature fails verification (forged)", "0", "2", "**VALID**", "Forged signature adds to `bad` only; Dave + Eve carry validity."],
        ["E", "Only Frank signed", "0", "0", "**UNKNOWN**", "An untrusted introducer’s signature, even if genuine, never validates a key."],
        ["F", "Only forged signatures (all fail verification)", "0", "0", "**INVALID**", "`bad > 0` and nothing counted."]], [0.9, 2.2, 0.4, 0.6, 0.8, 1.9], 8, align=["l", "l", "c", "c", "c", "l"])
    P("__Cross-check (Part II Tasks 1–2):__ the engine’s key ring was built with exactly this trust table; Alice’s key evaluated to VALID (full = 1, marginal = 2), while a key signed only by one marginal introducer (Gina) evaluated to UNKNOWN and produced the ‘signature valid but signer not validated’ warning.", 9)
    FIG("p5_trust", 6.2, "Left: Alice’s key in Bob’s web of trust. Right: the same question under a hierarchical CA.", "fig_trust")
    H3("Task 5.2 – Changing the trust assumption: hierarchical CAs (2 marks)")
    CAPT("t5change", "What is replaced, removed and added when moving from web of trust to a CA hierarchy")
    TBL(["", "Web of trust (PGP)", "Hierarchy (S/MIME)"], [
        ["**Decision replaced**", "‘Is this key signed by enough introducers __I__ have rated?’ (counting full/marginal owner-trust)", "‘Is there a chain of valid issuer signatures from this certificate to a **trust anchor** in my store?’"],
        ["**Removed**", "Per-introducer owner-trust levels; the counting thresholds; the user as the judge of each introducer.", "—"],
        ["**New checks**", "—", "**Path construction** (find issuers); **trust anchors** (the root set is the single trust decision); **basicConstraints** (issuer must be a CA, `pathLen`), key usage `keyCertSign`; validity of every certificate; revocation of every certificate in the path; name matching."]], [1.2, 2.7, 2.7], 8.4)
    CODE("""// core chain-validation loop (inside ValidateCertificate, Task 4.3)
 chain <- [Cert];  cur <- Cert;  depth <- 0
 WHILE cur NOT IN TrustedRoots DO
    issuer <- FIND(Intermediates UNION TrustedRoots, subject = cur.issuer, keyID = cur.authorityKeyID)
    IF issuer = NULL THEN RETURN NO_PATH END IF
    IF NOT VERIFY(issuer.publicKey, HASH(cur.toBeSigned), cur.signature) THEN RETURN BAD_SIGNATURE END IF
    IF issuer.basicConstraints.CA <> TRUE THEN RETURN ISSUER_NOT_CA END IF
    IF issuer.pathLen defined AND depth > issuer.pathLen THEN RETURN PATHLEN_EXCEEDED END IF
    IF cur is not within issuer's name constraints THEN RETURN NAME_CONSTRAINT END IF
    depth <- depth + 1;  APPEND issuer TO chain;  cur <- issuer
 END WHILE""")
    P("**Why a compromised intermediate CA differs from a compromised introducer.** __In the web of trust__ trust is spread over many individuals and thresholded: a compromised **marginal** introducer can contribute one signature, which by itself validates nothing (two are needed); only a compromised **full** introducer is dangerous, and even then the damage is limited to the keys that introducer actually signed or is persuaded to sign, and every verifier decided independently whether to trust them. __In a hierarchy__ trust is **transitive and structural**: every verifier trusts the root, the root trusts the intermediate, so an attacker holding an intermediate’s private key can mint a certificate for **any subject the intermediate may certify** (for the Issuing CA: every employee and server of the hospital), and every verifier will accept it, with no threshold and no individual judgement. The blast radius is the entire subtree. Recovery is also different: the root must revoke the intermediate (one CRL entry) and every certificate below it becomes untrusted at once – effective but disruptive – whereas a compromised introducer is handled by each user individually changing owner trust. This is why intermediates have `pathLen` and name constraints, and why roots stay offline.")
    H3("Task 5.3 – Changing the requirement: HTTPS client authentication (2 marks)")
    CAPT("t5state", "State held by the server after it has received the client’s Certificate message")
    TBL(["State element", "Meaning", "Known at this point?"], [
        ["`clientCertPresent`", "The client sent a certificate chain (non-empty).", "**Yes** – verified by receiving it."],
        ["`pathValid`", "Chain to a trusted __client__ CA, signatures, CA constraints OK.", "**Can be decided now** (needs only the Certificate message and local trust anchors)."],
        ["`timeValid`, `usageOK`", "All certificates in date; `extendedKeyUsage` contains clientAuth.", "**Can be decided now.**"],
        ["`notRevoked`", "CRL/OCSP status of the certificate and issuers.", "**Can be decided now**, if revocation data is reachable (otherwise fail closed)."],
        ["`possessionProven`", "The client holds the private key: signature in `CertificateVerify` over the handshake transcript verifies with the certificate’s public key.", "**Not yet** – arrives in the __next__ message. A certificate alone is public and replayable; without this proof anyone can present Alice’s certificate."],
        ["`identity`", "The account/role the certificate subject maps to.", "Remains to be derived after the above hold."],
        ["`authorised`", "That identity may use the requested resource.", "**Remains to be decided** – authentication is not authorisation."]], [1.4, 3.3, 1.9], 8.2)
    CODE("""ALGORITHM AcceptClient(ClientChain, CertificateVerify, Transcript, TrustedClientCAs, CRLs, Allowed, Resource, Now)
 OUTPUT: (ACCEPT, identity)  or  (REJECT, alertCode)
 BEGIN
   IF ClientChain is empty THEN RETURN (REJECT, CERTIFICATE_REQUIRED) END IF
   leaf <- ClientChain[0]
   r <- ValidateCertificate(leaf, NONE, "clientAuth", TrustedClientCAs, ClientChain[1..], CRLs, Now)   // path, dates, usage, revocation (Task 4.3)
   IF r <> OK THEN RETURN (REJECT, BAD_CERTIFICATE + r) END IF
   IF NOT VERIFY(leaf.publicKey, HASH(Transcript), CertificateVerify.signature) THEN RETURN (REJECT, DECRYPT_ERROR) END IF   // proof of possession
   identity <- MAP(leaf.subject, leaf.subjectAltName)                                                  // e.g. CN = lab-client-1
   IF identity = NULL OR (identity, Resource) NOT IN Allowed THEN RETURN (REJECT, ACCESS_DENIED) END IF      // authorisation, HTTP 403
   RETURN (ACCEPT, identity)
 END""")
    CAPT("t5compare", "Web-server certificate versus e-mail signer certificate")
    TBL(["Question", "Web server certificate (TLS)", "E-mail signer’s certificate (S/MIME)"], [
        ["Who is the verifier?", "The client’s browser/app, **live**, during the handshake, acting for the user.", "The recipient’s mail client, often **offline and long after** signing; the sender is not present."],
        ["What identity is compared?", "The **hostname the user chose** (typed or linked) against DNS names in the certificate. The expected name is known __before__ the connection and is not supplied by the peer.", "The **email address claimed inside the message** (From) against the rfc822 name in the certificate. The claim comes __from the sender__ – the attacker – so it must be compared; a valid certificate for another address proves nothing."],
        ["Proof of possession", "Handshake signature (`CertificateVerify`/ServerKeyExchange) binds the certificate to this live session.", "The message signature itself; there is no live challenge, so freshness needs timestamps/IDs."],
        ["Purpose / name type", "extendedKeyUsage serverAuth; `dNSName` SAN", "emailProtection; `rfc822Name` SAN"],
        ["Revocation timing", "Checked now (OCSP stapling, CRL).", "What matters is status __at signing time__; later revocation must not silently void old, legitimate signatures, so timestamps matter."]], [1.4, 2.6, 2.6], 8.2)

    # ----------------------------------------------------- 5.4 header + spam
    H3("Task 5 coverage block – e-mail header analysis and spam detection")
    t5 = J("t5")
    P("**Header analysis.** The headers of one phishing message (all invented, `.test`/`.example` domains) were inspected field by field.")
    CODE("\n".join(t5["header_analysis"]["raw"]), 7.6, title="Raw headers analysed")
    CAPT("t5hdr", "Header fields: visible identity, delivery path and authentication evidence kept apart")
    TBL(["Layer", "Field", "Value / observation"], [
        ["**Visible identity** (what the user sees – forgeable)", "From", "“Central Lab” <lab@hospital.test>"],
        ["", "Reply-To", "payments@hospital-billing.example – a **different domain**: replies are steered away from the claimed sender"],
        ["**Delivery path** (what actually happened)", "Return-Path (envelope sender)", "bounce@mail-relay.evil.test – differs from From; SPF is evaluated on __this__ domain"],
        ["", "Received (bottom = first hop)", "from mailer.evil.test [203.0.113.99] → our MX: the true origin"],
        ["", "Received (top = last hop)", "added by our own MX – the only hop we can trust"],
        ["", "Message-ID", "<9f3a@mailer.evil.test> – generated by the attacker’s system, not hospital.test"],
        ["", "Date", "03:35 UTC = 09:05 +0530, consistent with the first Received time – no clock anomaly"],
        ["**Authentication evidence**", "Authentication-Results", "spf=fail, dkim=none, dmarc=fail header.from=hospital.test – the receiving MTA’s own verdict"]], [1.7, 1.6, 3.3], 8.2)
    P("**Score-based classifier.** Seven content/header indicators (F1–F7) and four authentication indicators (A1–A4); the score is the sum of the weights, and a message is classed as spam/phishing when the score reaches the threshold.")
    CAPT("t5ind", "Indicators and weights")
    TBL(["ID", "Indicator", "Weight"], [["F1", "Reply-To domain differs from From domain", "+2"], ["F2", "Return-Path domain differs from From domain", "+1"], ["F3", "Urgency / credential words (urgent, verify, password, wire, gift card, …)", "+1 each, max +3"], ["F4", "Link text or IP-address link differs from the real target", "+2"],
        ["F5", "Subject mostly capital letters", "+1"], ["F6", "Message-ID domain differs from From domain", "+1"], ["F7", "Date missing or implausible", "+1"], ["A1", "SPF fail (+2) / softfail (+1)", "+2 / +1"], ["A2", "DKIM fail or none", "+1"], ["A3", "DMARC fail", "+2"], ["A4", "DMARC pass (evidence the visible domain is genuine)", "−2"]], [0.5, 4.8, 1.3], 8.2, align=["c", "l", "c"])
    CODE("""ALGORITHM ScoreMessage(Msg, Auth, Threshold)
 OUTPUT: (score, label, firedIndicators)
 BEGIN
   score <- 0
   IF Msg.ReplyToDomain <> Msg.FromDomain THEN score <- score + 2 END IF                                   // F1
   IF Msg.ReturnPathDomain <> Msg.FromDomain THEN score <- score + 1 END IF                                // F2
   score <- score + MIN(3, COUNT(urgencyWords IN Msg.subject || Msg.body))                                 // F3
   IF Msg.hasMismatchedOrIPLink THEN score <- score + 2 END IF                                             // F4
   IF capitalFraction(Msg.subject) > 0.6 THEN score <- score + 1 END IF                                    // F5
   IF Msg.MessageIDDomain <> Msg.FromDomain THEN score <- score + 1 END IF                                 // F6
   IF Msg.dateMissingOrImplausible THEN score <- score + 1 END IF                                          // F7
   IF Auth.spf = FAIL THEN score <- score + 2 ELSE IF Auth.spf = SOFTFAIL THEN score <- score + 1 END IF   // A1
   IF Auth.dkim IN {FAIL, NONE} THEN score <- score + 1 END IF                                             // A2
   IF Auth.dmarc = FAIL THEN score <- score + 2 END IF                                                     // A3
   IF Auth.dmarc = PASS THEN score <- score - 2 END IF                                                     // A4
   IF score >= Threshold THEN RETURN (score, SPAM_OR_PHISH, fired) ELSE RETURN (score, HAM, fired) END IF
 END""")
    sp = t5["spam"]; m = sp["main"]
    P(f"**Threshold and evaluation.** The labelled set has 12 invented messages (6 legitimate, 6 hostile; the set deliberately contains the hard cases: a legitimate mailing-list message, a legitimate forwarded message, a genuine ‘URGENT’ alert, a look-alike domain, and a phish from a compromised genuine account). A sweep over thresholds 2–8 (Figure {REF('fig_spam')}, left) gives the fewest total errors at **threshold = {m['threshold']}** (FP = {m['fp']}, FN = {m['fn']}), which is the value used. Because the set is tiny, the threshold is a demonstration choice, not a tuned value.")
    CAPT("t5spam", f"Classifier output, threshold {m['threshold']} (FP = false positive, FN = false negative)")
    TBL(["ID", "Class", "Description", "Score", "Outcome"], [[r["id"], r["label"], r["desc"], str(r["score"]), "**" + r["outcome"] + "**" if r["outcome"] in ("FP", "FN") else r["outcome"]] for r in m["rows"]], [0.4, 0.5, 4.3, 0.5, 0.7], 8, align=["c", "c", "l", "c", "c"])
    c = sp["content_only"]
    P(f"**Result:** TP = {m['tp']}, FP = {m['fp']}, FN = {m['fn']}, TN = {m['tn']} → precision {m['precision']:.2f}, recall {m['recall']:.2f}. **False positive (H3):** a legitimate message relayed by a mailing list that rewrote the body: DKIM breaks, DMARC fails, Reply-To and Return-Path point at the list – every authentication indicator fires although the sender is genuine. **False negative (S4):** a phish sent from a __compromised genuine mailbox__: SPF, DKIM and DMARC all pass, so the authentication indicator **lowers** the score (−2); the content indicators are too weak to compensate. Without the authentication indicators (content only, same threshold) the result is FP = {c['fp']}, FN = {c['fn']}: authentication evidence removes the false positive H6 (a tracked link from a domain proven genuine by a DMARC pass) and raises the score of spoofs (for example S1 from 7 to 12), but it cannot see a hostile message that originates from a legitimately authenticated sender.")
    FIG("t5_t2_plots", 6.4, "Left: classifier errors versus threshold with and without authentication indicators. Right: stranger-key validation, web of trust versus CA (Part II Task 2.4).", "fig_spam")
    P("**Authentication evidence is evidence, not a verdict.** SPF/DKIM/DMARC answer ‘was this message sent or authorised by the domain it shows?’ – they say nothing about whether the content is harmful. Hence they enter as weighted indicators (raising the score on failure, lowering it on a DMARC pass) and are combined with content signals; treating them as the whole solution would pass H-class mistakes and S4/S3-type attackers who own a domain with perfect authentication (S3 was caught only by its content indicators).")
    BOX("Rubric check – Task 5", ["5.1 ✔ algorithm with collection, signature verification, counting, explicit condition, three results, revoked/expired handling; applied to the table (cases A–F).  5.2 ✔ replaced/removed/new, chain-validation loop, compromise comparison.  5.3 ✔ state table, acceptance pseudocode, server-vs-email trust comparison.  Header/spam ✔ field analysis, 11 indicators, threshold, 12-message evaluation, FP and FN analysis, link to SPF/DKIM/DMARC."])

    # ============================================================= TASK 6
    H2("TASK 6 – DESIGN CHALLENGE: SECURE COMMUNICATION FOR A HOSPITAL NETWORK (13 marks)", True)
    H3("Stage 1 – Interpret the problem (2 marks)")
    CAPT("t6s1", "Assets, attackers, objectives, constraints and decisions for each communication need")
    TBL(["", "Need A – branch ↔ laboratory link", "Need B – lab reports to doctors by e-mail", "Need C – appointment-booking web service"], [
        ["**Assets**", "All inter-site traffic: patient data, orders, results; integrity of that traffic.", "Report content; the __authorship__ of the report (it drives treatment).", "Patients’ identities, appointment data; the patient’s trust that the site is the hospital’s."],
        ["**Attacker**", "On-path observer able to read, modify, inject, **capture and replay** packets.", "Anyone on the mail path (relays, mail servers, mailbox providers); a forger posing as the lab; a __repudiating sender__.", "Network eavesdropper; a phishing site imitating the hospital; active modifier."],
        ["**Objectives**", "Confidentiality, integrity, **origin authentication of the two sites**, **replay rejection**.", "Confidentiality for **one named reader**, integrity, origin authentication, **non-repudiation of origin**.", "**Server authentication** to the browser, confidentiality and integrity in transit."],
        ["**Constraints**", "Bulk, mixed-protocol traffic; no change to every application; both ends controlled by the hospital group.", "**Store-and-forward**, recipient offline, message kept for years, reader and sender share no secret.", "Anonymous clients; **no shared secret in advance**; consumer browsers with pre-installed trust anchors."],
        ["**Decisions**", "At which layer? which mode? how are keys established and renewed?", "What is signed, in what order with encryption? whose certificates, validated how?", "Who issues the server certificate? what versions and algorithms are allowed?"]], [0.9, 1.9, 1.9, 1.9], 8, firstbold=True)
    H3("Stage 2 – Strategy and justification (2 marks)")
    CAPT("t6s2", "Mechanism chosen for each need and why the alternatives were rejected")
    TBL(["Need", "Chosen", "Why its security principle fits this requirement", "Rejected / why"], [
        ["A", "**IPsec ESP, tunnel mode, gateway-to-gateway**, IKE with certificates", "Protects __everything__ crossing the link without touching applications; carries a **per-packet sequence number and replay window**, which is the stated replay requirement; tunnel mode hides inner addresses; keys refresh automatically.", "AH alone: no confidentiality. AH+ESP: redundant with authenticated encryption and breaks under NAT. Transport mode: each host would need IPsec and inner headers stay visible. TLS per application: every application must change, and replay protection is per connection, not per packet."],
        ["B", "**S/MIME, sign-then-encrypt**, certificates from the hospital CA", "A signature made with the lab’s __private__ key can be verified by any third party later – the basis of **non-repudiation**; encryption to Dr. Rao’s public key keeps the report unreadable to relays and while stored; the hospital already has a CA, so identities are validated by chain, not by personal introductions.", "**TLS between mail servers:** protects only each hop, leaves the report in clear on every server, and TLS authenticates with symmetric keys known to both ends, so a recording is not evidence against the sender – it cannot give per-message non-repudiation for a message that is stored and forwarded. **PGP:** needs web-of-trust decisions by each doctor; no central revocation."],
        ["C", "**TLS 1.3**, server certificate from a CA in browsers’ trust stores", "The browser must verify the server with **no prior relationship**: a certificate chain to a pre-installed anchor does exactly that; the handshake gives forward-secret keys and an authenticated, encrypted channel.", "IPsec: patients have no VPN client or pre-arranged SA. S/MIME: not interactive. A private hospital CA: browsers would not trust it."]], [0.4, 1.4, 2.5, 2.3], 7.9, align=["c", "l", "l", "l"])
    P("**Same mechanism for more than one need?** TLS (mutual) could also protect the site link, and the same hospital CA can issue the IPsec gateway, S/MIME and internal-server certificates – so the **PKI is shared** while the **protection mechanisms are not**: replay rejection per packet for arbitrary traffic (IPsec), transferable evidence per message (S/MIME) and zero-setup server authentication (TLS) are different properties.", 9.5)
    FIG("p6_arch", 6.3, "Chosen design: one mechanism for each need, one PKI behind them.", "fig_arch")
    H3("Stage 3 – State, trust and key ownership (2 marks)")
    CAPT("t6s3", "What must be kept or verified at each decision")
    TBL(["Mechanism", "State / trust definition", "Events that change it", "Verified before it is updated / trusted"], [
        ["**IPsec SA** (A)", "Per direction: SPI, keys, algorithm, `Highest`, `Window` (W bits), lifetime, traffic selectors. ‘Highest = largest __authentic__ sequence number accepted.’", "Accepted packet (window slides or bit set); re-key (new SA, fresh window); expiry (SA deleted); sequence exhaustion (sender stops, re-keys).", "**ICV verified before** any change to `Highest`/`Window`; SA found by SPI; lifetime valid; for IKE: both peers’ signatures over the exchange."],
        ["**S/MIME keys and certificates** (B)", "**Issues:** Hospital Issuing CA (under an offline root). **Stores:** the lab’s private key in a protected signing device; Dr. Rao’s private key on his device; public certificates in a directory and attached to messages. **Renews:** before expiry, with an overlap. **Revokes:** CRL (and OCSP) published by the CA.", "Issuance, renewal, revocation, expiry.", "**Verifier checks** (Task 4.3): chain to the root, CA constraints, dates, usage, **address equals certificate**, revocation. **Compromise:** revoke immediately, re-issue, treat signatures dated after the compromise as untrusted; timestamps keep earlier ones verifiable."],
        ["**TLS certificate** (C)", "Server key + certificate from a public CA, renewed automatically; stapled OCSP.", "Renewal (about every 90 days), revocation.", "Browser checks chain, dates, **hostname**, serverAuth, minimum protocol version. **Compromise:** revoke, re-issue, rotate key, force TLS 1.3 forward-secret suites."]], [1.1, 2.2, 1.4, 1.9], 7.8)
    H3("Stage 4 – Complete pseudocode (4 marks): e-mail report (sender and receiver) and the IPsec link")
    CODE("""ALGORITHM LabSendReport(Report, DoctorAddr, LabPrivKey, LabCert, Directory, TrustedRoots, CRLs, Now)
 INPUT:  Report - laboratory report;  DoctorAddr - e.g. dr.rao@hospital.test;  LabPrivKey, LabCert;  Directory - certificate lookup;  TrustedRoots, CRLs, Now
 OUTPUT: (SENT, Envelope, evidence)  or  (ERROR, reason)
 BEGIN
   IF Report is empty THEN RETURN (ERROR, EMPTY_REPORT) END IF
   IF NOT (LabCert.notBefore <= Now AND Now <= LabCert.notAfter) THEN RETURN (ERROR, OWN_CERT_EXPIRED) END IF
   DocCert <- LOOKUP(Directory, DoctorAddr)                                                      // preprocessing: key lookup
   IF DocCert = NULL THEN RETURN (ERROR, NO_CERTIFICATE_FOR_DOCTOR) END IF
   r <- ValidateCertificate(DocCert, DoctorAddr, "keyEncipherment", TrustedRoots, Directory.CAs, CRLs, Now)    // certificate validation
   IF r <> OK THEN RETURN (ERROR, DOCTOR_CERT_ + r) END IF                                       // never encrypt to an unvalidated key
   id <- RANDOM_KEY(128);  signed <- Report || DoctorAddr || Now || id
   sig <- SIGN(LabPrivKey, HASH(signed))                                                          // 1. sign first: non-repudiation of origin
   block <- (Report, DoctorAddr, Now, id, sig, LabCert)
   Ks <- RANDOM_KEY(256);  C <- SYM_ENCRYPT(Ks, block)                                           // 2. then encrypt: only the doctor can read
   WK <- PK_ENCRYPT(DocCert.publicKey, Ks);  ERASE(Ks)                                           // 3. key sealed for the named doctor
   Envelope <- ENCODE(algorithmIDs, WK, C)
   evidence <- (id, Now, HASH(signed), sig)                                                       // retained by the lab: what it signed and when
   RETURN (SENT, Envelope, evidence)
 END

ALGORITHM DoctorReceiveReport(Envelope, DocPrivKey, DoctorAddr, ExpectedLabAddr, TrustedRoots, Intermediates, CRLs, SeenIDs, Now, MaxAge)
 OUTPUT: (ACCEPT, Report, labIdentity)  or  (REJECT, reason)
 BEGIN
   (WK, C) <- DECODE(Envelope);  IF decoding fails THEN RETURN (REJECT, MALFORMED) END IF
   Ks <- PK_DECRYPT(DocPrivKey, WK);  IF Ks = FAILURE THEN RETURN (REJECT, NOT_FOR_THIS_KEY) END IF
   block <- SYM_DECRYPT(Ks, C);  ERASE(Ks);  IF block = FAILURE THEN RETURN (REJECT, DECRYPTION_OR_INTEGRITY_FAILURE) END IF
   (Report, Addr, stamp, id, sig, LabCert) <- PARSE(block)
   IF Addr <> DoctorAddr THEN RETURN (REJECT, NOT_ADDRESSED_TO_ME) END IF
   r <- ValidateCertificate(LabCert, ExpectedLabAddr, "digitalSignature", TrustedRoots, Intermediates, CRLs, Now)
   IF r <> OK THEN RETURN (REJECT, LAB_CERT_ + r) END IF                                         // chain, dates, usage, address, revocation
   IF VERIFY(LabCert.publicKey, HASH(Report || Addr || stamp || id), sig) <> TRUE THEN RETURN (REJECT, BAD_SIGNATURE) END IF
   IF Now - stamp > MaxAge OR id IN SeenIDs THEN RETURN (REJECT, STALE_OR_REPLAYED) END IF
   ADD id TO SeenIDs;  STORE (Report, stamp, id, sig, LabCert) AS evidence                       // doctor keeps third-party-verifiable proof
   RETURN (ACCEPT, Report, LabCert.subject)
 END

ALGORITHM GatewayOutbound(Packet, SPD, SAD)                                   // IPsec link, sender side
 OUTPUT: (SENT, spi, seq) or (DROPPED/QUEUED, reason)
 BEGIN
   policy <- MATCH(SPD, Packet.src, Packet.dst, Packet.proto)
   IF policy = NULL OR policy.action = DISCARD THEN RETURN (DROPPED, NO_POLICY) END IF           // default deny between sites
   SA <- LOOKUP(SAD, policy)
   IF SA = NULL THEN TRIGGER IKE_ESTABLISH(policy);  QUEUE Packet;  RETURN (QUEUED, NO_SA_YET) END IF
   IF SA.seq >= SA.maxSeq OR SA.expired THEN TRIGGER IKE_REKEY(SA);  QUEUE Packet;  RETURN (QUEUED, REKEY) END IF      // never wrap or reuse a sequence number
   SA.seq <- SA.seq + 1
   plain <- Packet || PAD || padLength || 4                                  // next header = IP-in-IP (tunnel)
   C <- AEAD_ENCRYPT(SA.key, NONCE(SA.seq), plain, aad = SA.SPI || SA.seq)   // confidentiality + ICV in one operation
   RETURN SEND(NewIPHeader(SA.gwSrc, SA.gwDst) || SA.SPI || SA.seq || C)
 END

ALGORITHM GatewayInbound(Packet, SAD, SPD)                                    // receiver side
 BEGIN
   (verdict, reason, inner) <- ProcessInboundESP(Packet, SAD)               // Task 3.3: SA lookup, ICV, replay check, state update
   IF verdict = DROP THEN LOG(reason);  RETURN SILENT_DISCARD END IF         // internal log only; nothing sent back
   IF inner.src, inner.dst NOT WITHIN SA.trafficSelectors THEN LOG(SELECTOR_MISMATCH);  RETURN SILENT_DISCARD END IF
   FORWARD inner INTO the protected network
 END""", 7.4)
    H3("Stage 5 – Desk-check: one laboratory report for Dr. Rao (1 mark)")
    CAPT("t6s5", "values → decisions → checks → accepted/rejected → result (symbolic key names)")
    TBL(["#", "Value", "Decision / check", "Outcome"], [
        ["1", "Report = “Pt 1001: Hb 13.2 g/dL”; DoctorAddr = dr.rao@hospital.test; Now = T", "Report non-empty? LabCert in date at T?", "yes; yes → continue"],
        ["2", "DocCert = Directory[dr.rao@hospital.test]; issuer = Issuing CA", "Found? `ValidateCertificate(DocCert, address, keyEncipherment, …)`: path DocCert → Issuing CA → Root ∈ TrustedRoots; CA flags OK; dates OK; address = SAN; serial not on CRL", "OK → proceed"],
        ["3", "id = n₁ (random 128-bit); signed = Report ‖ DoctorAddr ‖ T ‖ n₁", "digest = HASH(signed) = h", "h"],
        ["4", "LabPrivKey, h", "sig = SIGN(LabPrivKey, h) = σ", "σ"],
        ["5", "block = (Report, DoctorAddr, T, n₁, σ, LabCert); Ks = RANDOM", "C = SYM_ENCRYPT(Ks, block); WK = PK_ENCRYPT(DocCert.publicKey, Ks)", "Envelope = (WK, C); Ks erased; evidence = (n₁, T, h, σ) kept by the lab"],
        ["6", "Envelope arrives at Dr. Rao", "DECODE ok; Ks = PK_DECRYPT(DocPrivKey, WK) ≠ FAILURE", "Dr. Rao’s key is the only one that opens WK"],
        ["7", "C", "block = SYM_DECRYPT(Ks, C) ≠ FAILURE (authenticated encryption passes)", "parsed: Report, Addr, T, n₁, σ, LabCert"],
        ["8", "Addr = dr.rao@hospital.test", "Addr = DoctorAddr?", "yes → continue (otherwise NOT_ADDRESSED_TO_ME)"],
        ["9", "LabCert", "ValidateCertificate(LabCert, lab@hospital.test, digitalSignature, …): path, CA, dates, usage, address, CRL", "OK"],
        ["10", "h′ = HASH(Report ‖ Addr ‖ T ‖ n₁)", "VERIFY(LabCert.publicKey, h′, σ) → h′ = h?", "TRUE"],
        ["11", "Now′ − T ≤ MaxAge; n₁ ∉ SeenIDs", "fresh and unseen?", "yes → add n₁ to SeenIDs, store evidence"],
        ["**Final**", "", "", "**ACCEPT** – Report delivered to Dr. Rao with signer identity lab@hospital.test; the lab holds proof of what it signed and when; the doctor holds the signature σ"]], [0.45, 2.2, 2.7, 1.25], 7.9)
    H3("Stage 6 – Attack your own design (2 marks)")
    CAPT("t6s6", "Four attack scenarios: why hard, prediction, trace, verdict, residual risk")
    TBL(["", "A1 – IPsec packet replayed after a delay", "A2 – the laboratory’s signing key is stolen", "A3 – fake certificate for the doctor’s address", "A4 – TLS downgrade to an old protocol"], [
        ["**Why challenging**", "The replayed packet is __genuine__: its ICV is valid, so integrity alone cannot reject it.", "Every signature the thief makes is cryptographically perfect.", "The attacker supplies a convincing certificate carrying dr.rao@hospital.test.", "The attacker on the path edits the handshake to offer only old versions."],
        ["**Prediction**", "Rejected as a duplicate or too old; but a packet __never received__ and still inside the window will be accepted once.", "Accepted until the certificate is revoked and the revocation reaches the receiver; rejected afterwards.", "Rejected by the lab’s sender-side validation (no path to the hospital root) before anything is encrypted.", "Refused: the server accepts only TLS ≥ 1.2 with AEAD suites; TLS 1.3 adds a downgrade sentinel."],
        ["**Trace**", "Gateway B: Highest = 100, W = 32. Replay seq 100 → ICV valid; d = 0, bit 0 set → `REPLAY_DUPLICATE`. Replay seq 60 (captured, never delivered) → d = 40 ≥ 32 → `REPLAY_TOO_OLD`. Replay seq 84 (captured, never delivered) → d = 16, bit clear → **ACCEPT once**; replay again → DUPLICATE.", "Receiver: Step 9 `ValidateCertificate`: path OK, dates OK, address OK, revocation: if the CRL already lists the serial → `CERT_REVOKED`; if the CRL is older than the theft → `OK` → report **accepted**.", "`ValidateCertificate(DocCert, …)`: issuer is a rogue CA → `FIND` returns NULL → `NO_PATH_TO_TRUSTED_ROOT` → `(ERROR, DOCTOR_CERT_…)`. If the attacker holds a real hospital certificate for __another__ address: `IDENTITY_MISMATCH`.", "Server: ClientHello offers max TLS 1.0 → no common version/cipher → handshake failure; connection refused, no data exchanged."],
        ["**Stopped? critical check**", "**Yes for duplicates and old packets** – critical: replay check after ICV. Not stopped for a delayed, never-delivered packet inside the window.", "**Only after revocation** – critical: revocation check (and CRL freshness).", "**Yes** – critical: path to `TrustedRoots` and address equality.", "**Yes** – critical: server minimum-version and cipher policy."],
        ["**Assumption that can fail / residual risk**", "‘A packet inside the window that the receiver never saw is legitimate.’ Residual: delay of at most W packets; effect bounded to one delayed packet.", "‘The key stays secret.’ Residual: window between theft and revocation reaching receivers; the lab could also __claim__ theft to repudiate – mitigated by protected signing devices, short-lived certificates and trusted timestamps.", "‘The CA identity-proofs correctly.’ If the CA were tricked into issuing a certificate for Dr. Rao’s address, the check would pass – mitigated by verifying fingerprints out of band.", "‘All clients support TLS ≥ 1.2.’ Residual: availability – very old browsers cannot book appointments."],
        ["**Evidence in Part II**", "Task 3.B: tests i, ii, ii-b, iii, edge-in, edge-out.", "Task 2.2: case S4 (revoked → rejected); Task 6: revoked keys never wrapped.", "Task 2.2: S2 (untrusted CA), S3 (address mismatch).", "Task 4.4: legacy client refused after the fix."]], [0.8, 1.45, 1.45, 1.45, 1.45], 7.4, firstbold=True)
    BOX("Rubric check – Task 6", ["S1 ✔ per-need assets, attackers, objectives, constraints, decisions.  S2 ✔ mechanism per need with principle-based justification and rejected options.  S3 ✔ state and trust definitions.  S4 ✔ email sender/receiver plus IPsec outbound/inbound pseudocode.  S5 ✔ eleven-step desk-check.  S6 ✔ four attacks with prediction, trace, critical check, residual risk."])
