import os
from rb_lib import *

CODEDIR = os.path.dirname(__file__)


def build():
    t3 = J("t3"); t6 = J("t6"); t2 = J("t2")
    H1("INTEGRATED CONCLUSION AND VIVA PREPARATION")
    P("The two parts of this assignment form one argument. Part I derived, by reasoning and hand traces, **where the decisions in a secure-mail, IPsec and web-trust design must sit**; Part II built and attacked each of those decisions and measured what happened. The table lists, for each topic, the design claim, the evidence that tested it, and the limit.", 9.5)
    CAPT("conc", "Design claim, evidence and limit by topic")
    TBL(["Topic", "Design claim (Part I)", "Evidence (Part II)", "Limit / residual risk"], [
        ["Hybrid mail (PGP-style)", "Sign → compress → encrypt with a session key → wrap for each recipient; verify before trusting.", "PK ops = 2 + (n − 1); message grows exactly 266 B per recipient; all 7 tamper tests fail closed with distinct exit codes.", "A valid signature does not mean a trusted identity (exit 20 case)."],
        ["Certificate validation", "A signature plus a valid date is not authenticity; chain, CA constraints, usage, address and revocation are all required.", "7 S/MIME cases rejected at the predicted check; missing-intermediate case repaired by re-sending the chain.", "CA compromise has subtree-wide impact; CRL freshness."],
        ["IPsec anti-replay", "ICV first, then replay check, then state update.", "8 replay/boundary predictions matched; window edges at W−1 / W correct; modified sequence numbers fail the ICV.", "A never-delivered packet inside the window is accepted once; timing differences of a few µs between drop reasons."],
        ["IPsec coverage and NAT", "ESP ICV excludes the outer header; AH covers immutable addresses.", "AH fails after NAT; ESP tunnel survives; transport-mode ESP breaks the encrypted checksum.", "Real deployments need NAT-T."],
        ["HTTPS and mTLS", "Check chain, validity, hostname; authenticate the client by certificate and then authorise it.", "5 predictions matched; 401/403 separated from handshake failure; weak configuration refused after hardening.", "Old clients lose service; optional client-auth listeners rely on handler checks."],
        ["SPF/DKIM/DMARC", "Alignment ties the authenticated domain to the visible From.", "8 predicted outcomes matched incl. legitimate failure (mailing list) and SPF-pass/DKIM-pass/DMARC-fail (spoof).", "Not integrity or confidentiality; not an end-to-end identity."],
        ["Key management at scale", "Only ACTIVE keys may be wrapped; revocation overrides dates.", "Revoked/expired recipients cannot decrypt; linear cost after fixing an index/concatenation defect; 266 B per recipient.", "At 200,000 subscribers, delivery and group-key trade-offs dominate."]], [1.2, 1.9, 2.1, 1.4], 7.7)
    P("**Final recommended architecture for the hospital network** (Part I Task 6, confirmed by Part II): IPsec ESP tunnels between the branch gateways and the laboratory (IKE with certificates, fresh DH at every re-key, 32-packet or larger replay windows); S/MIME sign-then-encrypt for laboratory reports with certificates from the hospital CA hierarchy (offline root, constrained issuing CA, CRL/OCSP, protected signing key); TLS 1.3 only, AEAD/ECDHE suites, HSTS and mutual TLS for laboratory APIs; SPF, DKIM and DMARC (staged to `reject`) for the hospital domain; and a key store whose state machine – ACTIVE only – is enforced before any key is wrapped.", 9.5)
    H2("Viva preparation – questions the evidence should let me answer")
    CAPT("viva", "Likely verification questions and where the answer is")
    TBL(["Question", "Short answer", "See"], [
        ["Why sign before compressing and encrypting?", "The signature must verify against the original M; compression is not canonical; encryption then hides the signature.", "Part I Task 2.2"],
        ["Why is ICV checked before the window is updated?", "Otherwise one forged packet with a huge sequence number moves `Highest` and every genuine packet is dropped as too old.", "Part I Task 3.5; Part II 3.B iv"],
        ["Which exact line of the S/MIME pseudocode is the defect?", "The final ACCEPT: `TrustedRoots` is never used, so the certificate chosen by the sender is trusted.", "Part I Task 4.1"],
        ["Why can a compromised intermediate CA do more harm than a compromised introducer?", "Trust is transitive and unthresholded; everything under it is accepted by every verifier.", "Part I Task 5.2"],
        ["Why does TLS between mail servers not give non-repudiation?", "It authenticates hops with keys both ends know and leaves no transferable evidence; messages are stored and forwarded after the session.", "Part I Task 6 Stage 2"],
        ["Why was a packet delayed by W/2 accepted but one delayed by 40 dropped?", "Inside the window and unseen ⇒ accepted once; outside the window the receiver can no longer tell.", "Part II 3.B"],
        ["How can SPF and DKIM pass but DMARC fail?", "They authenticated the attacker’s own domain, not the visible From domain; alignment fails.", "Part II 5 (M4)"],
        ["Why could a revoked recipient not decrypt although they own a valid private key?", "No wrapped key was produced for them; the message itself excludes them.", "Part II 6.4"],
        ["What was the largest cost at 10,000 recipients and why?", "Lookup and assembly, not RSA: an unindexed query and repeated concatenation; fixed by an index and a join.", "Part II 6.5"],
        ["What are the limits of your evidence?", "Simulated IPsec/DNS; Python timings; reused key material for large lists; 12-message classifier set.", "Guide, Section D"]], [2.4, 3.2, 1.0], 8)

    H1("REFERENCES")
    for t in ["Kent, S., “IP Authentication Header”, RFC 4302; “IP Encapsulating Security Payload (ESP)”, RFC 4303; Kent, S., Seo, K., “Security Architecture for the Internet Protocol”, RFC 4301.",
              "Kaufman, C. et al., “Internet Key Exchange Protocol Version 2 (IKEv2)”, RFC 7296.",
              "Callas, J. et al., “OpenPGP Message Format”, RFC 4880 (superseded by RFC 9580); Ramsdell, B., Turner, S., “S/MIME Version 4.0 Message Specification”, RFC 8551; Housley, R., “Cryptographic Message Syntax (CMS)”, RFC 5652.",
              "Cooper, D. et al., “Internet X.509 Public Key Infrastructure Certificate and CRL Profile”, RFC 5280.",
              "Rescorla, E., “The Transport Layer Security (TLS) Protocol Version 1.3”, RFC 8446; NIST SP 800-52 Rev. 2, “Guidelines for the Selection, Configuration, and Use of TLS Implementations”.",
              "Kitterman, S., “Sender Policy Framework (SPF)”, RFC 7208; Crocker, D. et al., “DomainKeys Identified Mail (DKIM) Signatures”, RFC 6376; Kucherawy, M., Zwicky, E., “DMARC”, RFC 7489.",
              "Moriarty, K. et al., “PKCS #1: RSA Cryptography Specifications Version 2.2”, RFC 8017 (OAEP, PSS); McGrew, D., “An Interface and Algorithms for Authenticated Encryption”, RFC 5116.",
              "Stallings, W., Cryptography and Network Security: Principles and Practice (course text) – chapters on IP security, electronic mail security and web security."]:
        BUL([t], 9.2)

    H1("APPENDIX A – FILES, RUN INSTRUCTIONS AND RAW DATA")
    P("All code, raw results and figures are supplied in `CO4_code_and_data.zip` (test private keys are deliberately **not** included; every run regenerates them). Python 3 with the `cryptography` and `matplotlib` packages and OpenSSL 3.x are required. Run from the `code/` directory, in this order:", 9.5)
    CODE("python3 run_t1.py     # Task 1: key ring + PGP-style CLI runs, predictions, tamper tests   -> results/t1.json\npython3 run_t2.py     # Task 2: PKI, S/MIME cases, PGP comparison, 5,000-user model          -> results/t2.json\npython3 run_t3.py     # Task 3: ESP/AH/IKE-lite simulation, replay lab, NAT, timing            -> results/t3.json\npython3 run_t4.py     # Task 4: HTTPS/mTLS service on localhost, captures, downgrade lab        -> results/t4.json\npython3 run_t5.py     # Task 5: SPF/DKIM/DMARC, header analysis, spam classifier                 -> results/t5.json\npython3 run_t6.py     # Task 6: key store, five-recipient test, growth experiment               -> results/t6.json\npython3 figs.py       # regenerate the figures from results/*.json", 8)
    CAPT("files", "Source files")
    rows = []
    for f, d in [("pgpmail.py", "PGP-style hybrid engine, key ring, web-of-trust validity, CLI with exit codes"), ("pki.py", "Test certificate hierarchy and CRL"), ("esp.py", "ESP/AH, anti-replay window, IKE-lite, NAT rewrite, gateway"), ("mailauth.py", "SPF, DKIM, DMARC"),
                 ("run_t1.py", "Task 1 runner"), ("run_t2.py", "Task 2 runner"), ("run_t3.py", "Task 3 runner"), ("run_t4.py", "Task 4 runner"), ("run_t5.py", "Task 5 runner"), ("run_t6.py", "Task 6 runner")]:
        rows.append([f, d, str(len(open(os.path.join(CODEDIR, f)).read().splitlines()))])
    TBL(["File", "Purpose", "Lines"], rows, [1.6, 4.3, 0.7], 8.2, align=["l", "l", "c"])
    P("**Reproducibility note.** Operation counts, message sizes, accept/reject results and predictions are deterministic and repeat exactly; timings and the Monte-Carlo percentages vary slightly from run to run, so the tables in this report were generated from one recorded run.", 9.5)

    H1("APPENDIX B – SOURCE CODE")
    P("Complete source code of the student-written core (Part II). Libraries supply RSA/AES/SHA/X25519/ECDSA primitives and the OpenSSL CMS/TLS stacks used as cross-checks; the protocol logic is the student’s own.", 9.5)
    for f in ["pgpmail.py", "pki.py", "esp.py", "mailauth.py", "run_t1.py", "run_t2.py", "run_t3.py", "run_t4.py", "run_t5.py", "run_t6.py"]:
        H2(f"B – {f}", False)
        CODE(open(os.path.join(CODEDIR, f)).read(), 6.6)
