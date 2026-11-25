from rb_lib import *
from rb_lib import _font


def build():
    from docx.enum.section import WD_SECTION
    sec = doc.add_section(WD_SECTION.NEW_PAGE); sec.header.is_linked_to_previous = False; sec.footer.is_linked_to_previous = False
    hp = sec.header.paragraphs[0]
    for r in list(hp.runs): r._element.getparent().remove(r._element)
    for el in list(sec.header._element): 
        if el.tag.endswith("}p") and el is not hp._element: sec.header._element.remove(el)
    r = hp.add_run("CSA5103 – Cryptography and Network Security  |  Assignment 4 (CO4)  |  RAKSHITH R R  |  192324156"); _font(r, 8, False, False, RGBColor(0x55, 0x55, 0x55)); hp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp = sec.footer.paragraphs[0]; fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = fp.add_run("Page "); _font(r, 8, False, False, RGBColor(0x55, 0x55, 0x55))
    for kind, txt in (("begin", None), (None, " PAGE "), ("end", None)):
        rr = fp.add_run(); _font(rr, 8, False, False, RGBColor(0x55, 0x55, 0x55))
        if kind: fc = OxmlElement("w:fldChar"); fc.set(qn("w:fldCharType"), kind); rr._element.append(fc)
        else: it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = txt; rr._element.append(it)
    p = P("**SIMATS ENGINEERING**", 16, align="c", after=0, color=DARK); P("Department of Information Technology", 11, align="c", after=0); P("**CSA5103 – CRYPTOGRAPHY AND NETWORK SECURITY**", 12, align="c", after=2)
    P("**ASSIGNMENT 4 – CO4: STUDENT SUBMISSION REPORT**", 14, align="c", after=2, color=DARK)
    P("Part I – Algorithmic Design Through Pseudocode  |  Part II – Security Engineering: Implement, Test, Attack & Harden", 10, align="c", italic=True, after=2)
    P("CO4: Implement best security practices for IP, email and web services using PGP and S/MIME to enhance email security.", 9.5, align="c", after=8)
    TBL(["Field", "Details", "Field", "Details"], [
        ["Student Name", "RAKSHITH R R", "Register Number", "192324156"],
        ["Department / Programme", "Information Technology / B.Tech – AI&DS", "Academic Year / Semester", "4th year"],
        ["Faculty Name", "(to be filled by faculty)", "Nature of Assignment", "Individual"],
        ["Duration", "1 Week", "Maximum Marks", "Part I: 50  +  Part II: 50"],
        ["Date of Submission", "", "Date of Evaluation", ""]], [1.5, 1.8, 1.5, 1.8], 9, firstbold=False)
    P("**Environment (Part II).** Python 3 with the `cryptography` library for vetted primitives, OpenSSL 3.0 for S/MIME (`openssl cms`) and TLS capture (`openssl s_client`), SQLite for the key store. Every experiment ran on one machine, on localhost, with test keys generated at run time and test data invented by the student. The mathematical/protocol logic (message format, replay window, validators, SPF/DKIM/DMARC, key-state machine) is the student's own code; libraries supply only RSA/AES/SHA/X25519/ECDSA primitives and the OpenSSL CMS/TLS stacks used as independent cross-checks.", 9.5)
    P("**Contents of this report.** (1) Evaluation forms for Part I and Part II, (2) a guide mapping every rubric line to the place where its evidence appears, (3) conventions, (4) Part I – Tasks 1 to 6, (5) Part II – Tasks 1 to 6, (6) integrated conclusion and viva preparation, (7) references, (8) appendices with all source code, run instructions and raw outputs.", 9.5)

    # ------------------------------------------------------------------ evaluation form Part I
    H1("EVALUATION FORM – ASSIGNMENT 4, PART I (as issued; faculty columns left blank)")
    P("Algorithmic Design Through Pseudocode. Student name and register number filled in; marks, remarks, statuses and dates are for the evaluator.", 9, italic=True)
    CAPT("evalI", "Part I – mark sheet (rubric-based evaluation)")
    TBL(["Task", "Competency / assessment focus", "Max", "Marks awarded", "Evaluator remarks"], [
        ["1", "Diagnose and repair poor security pseudocode; identify design deficiencies, rewrite sender/receiver logic and defend the pseudocode design.", "6", "", ""],
        ["2", "Model PGP security requirements; formulate signing/compression/encryption order; design sender/receiver pseudocode; desk-check and challenge the design.", "8", "", ""],
        ["3", "Define IPsec ESP anti-replay state and decision rules; write processing pseudocode; desk-check and explain integrity-before-state-update. Include IPsec architecture, AH, ESP, SA bundles and key management.", "9", "", ""],
        ["4", "Identify the S/MIME certificate-validation defect; construct a failing input; repair the required logic and complete a regression check.", "7", "", ""],
        ["5", "Design PGP web-of-trust evaluation; adapt reasoning to hierarchical CA validation; design certificate-based HTTPS client authentication.", "7", "", ""],
        ["6", "Design a secure hospital communication solution; interpret threats and requirements, select mechanisms, define state/trust, write pseudocode, desk-check and attack-test the design.", "13", "", ""],
        ["", "**TOTAL**", "**50**", "", ""]], [0.4, 3.6, 0.45, 0.8, 1.2], 8.5, align=["c", "l", "c", "c", "l"])
    CAPT("rubI", "Part I – detailed evaluation rubric")
    rub1 = [("1.1", "At least five meaningful security-design deficiencies with reasons", 2), ("1.2", "Complete sender-side and receiver-side pseudocode with explicit order and checks", 3), ("1.3", "Clear design defence (pseudocode vs. programming code / informal English)", 1),
            ("2.1", "Input, output, objectives, constraints and sender/receiver decisions", 2), ("2.2", "Precise design hypothesis and justification of operation order", 1), ("2.3", "Complete PGP sender/receiver pseudocode and failure handling", 3),
            ("2.4", "Step-by-step desk-check with intermediate values", 1), ("2.5", "Modified condition, prediction and relevant trace", 1),
            ("3.1", "Precise Security Association replay state definition", 1), ("3.2", "Correct decision rules for new, in-window, old and duplicate packets; ICV ordering", 2), ("3.3", "Complete pseudocode, SA lookup, ICV check, replay processing and reasoned ACCEPT/DROP", 4),
            ("3.4", "Accurate manual trace for the given sequence and window size", 1), ("3.5", "Explanation of integrity verification before window update", 1),
            ("4.1", "Exact defect and explanation", 2), ("4.2", "Student-created failing input and decision trace", 2), ("4.3", "Minimal correction with trust, identity and revocation checks", 2), ("4.4", "Regression case and preserved correct behaviour", 1),
            ("5.1", "PGP web-of-trust pseudocode, signature checks and application to given trust table", 3), ("5.2", "CA hierarchy comparison and certificate-chain validation logic", 2), ("5.3", "HTTPS client-certificate state, acceptance logic and identity comparison", 2),
            ("6-S1", "Interpret assets, threats, security objectives and constraints", 2), ("6-S2", "Select and justify suitable mechanisms for each communication need", 2), ("6-S3", "Define state, trust, key ownership and verification requirements", 2),
            ("6-S4", "Complete language-independent pseudocode for email and one other need", 4), ("6-S5", "Desk-check with values, decisions and final result", 1), ("6-S6", "Three attack scenarios, prediction, trace, critical checks and residual risk", 2)]
    TBL(["Criterion", "Evaluation criteria", "Max", "Awarded"], [[a, b, str(c), ""] for a, b, c in rub1], [0.7, 4.7, 0.5, 0.7], 8.2, align=["c", "l", "c", "c"])
    CAPT("evidI", "Part I – mandatory submission evidence check (status to be marked by evaluator: ✓ present, P partly, ✗ missing)")
    TBL(["Task", "Evidence expected", "Status", "Evaluator notes"], [
        ["1", "Deficiency analysis, corrected sender/receiver pseudocode and design defence", "", ""], ["2", "Requirement model, design hypothesis, PGP pseudocode, desk-check and challenge trace", "", ""],
        ["3", "SA state definition, replay decision rule, pseudocode, packet trace and order-of-check explanation", "", ""], ["3", "IPsec coverage: architecture, transport/tunnel modes, AH, ESP, SA combinations and IKE/key management", "", ""],
        ["4", "Defect explanation, constructed failing certificate case, repaired logic and regression check", "", ""], ["5", "Web-of-trust evaluation, CA chain-validation loop and HTTPS client-certificate logic", "", ""],
        ["5", "Email header analysis and spam detection: header fields, SPF/DKIM/DMARC evidence, classifier indicators, threshold, labelled test results, false positives and false negatives", "", ""],
        ["6", "Threat/asset analysis, mechanism selection, state/trust definition, complete pseudocode, desk-check and three attack tests", "", ""],
        ["All", "Language-independent pseudocode follows the prescribed standard; reasoning and evidence support the final decisions", "", ""]], [0.5, 4.4, 0.7, 1.0], 8.2, align=["c", "l", "c", "l"])
    CAPT("chainI", "Part I – design evidence chain")
    TBL(["Evidence item", "Status", "Observation / reference"], [[x, "", ""] for x in ["Requirement interpretation and problem statement", "Assets, threats and security objectives", "Protocol logic / state / trust decision rules", "Pseudocode and sender/receiver processing sequence", "Manual trace / desk-check", "Attack, boundary and regression tests", "IPsec, PGP, S/MIME, certificate and email-header evidence", "Tables, diagrams and supporting working", "Student explanation / viva verification"]], [3.2, 0.8, 2.6], 8.2)
    P("**Overall remarks:** ____________________________________________________________________________________", 9); P("Total marks ____ / 50     Percentage ____ %     Performance / status ________________", 9)
    TBL(["Student signature", "Faculty signature", "Program Director"], [["\n\n", "\n\n", "\n\n"]], [2.2, 2.2, 2.2], 8.5, zebra=False)
    CAPT("chkI", "Part I – submission checklist (not separately marked) with the student's self-check")
    TBL(["Requirement", "Student self-check", "Evaluator"], [
        ["All six tasks attempted and task-wise marks recorded", "Yes – Tasks 1–6", "☐ Yes ☐ Partly ☐ No"], ["Pseudocode is language-independent and follows the prescribed standard", "Yes – convention stated in Section C of the guide", "☐ Yes ☐ Partly ☐ No"],
        ["Required reasoning, decision rules and failure handling are explicit", "Yes", "☐ Yes ☐ Partly ☐ No"], ["Manual traces / desk-checks are included", "Yes – Tasks 2.4, 3.4, 4.2, 5.1, 6-S5", "☐ Yes ☐ Partly ☐ No"],
        ["Attack, boundary and regression tests are included where required", "Yes – Tasks 2.5, 4.2/4.4, 6-S6", "☐ Yes ☐ Partly ☐ No"], ["IPsec and email-header / spam-detection syllabus coverage is addressed", "Yes – Task 3 coverage block; Task 5 header/spam block", "☐ Yes ☐ Partly ☐ No"],
        ["Task 6 design challenge is completed", "Yes", "☐ Yes ☐ No"], ["Viva / individual understanding verified", "Prepared – see viva notes in the integrated conclusion", "☐ Yes ☐ No"]], [3.3, 2.0, 1.3], 8.2)

    # ------------------------------------------------------------------ evaluation form Part II
    H1("EVALUATION FORM – ASSIGNMENT 4, PART II (as issued; faculty columns left blank)")
    P("Security Engineering: Implement, Test, Attack & Harden. Prerequisite: completion of Part I (this report, Part I). Environment: Python 3 + `cryptography`, OpenSSL 3.0, SQLite (see the title page).", 9, italic=True)
    CAPT("evalII", "Part II – task-wise mark summary")
    TBL(["Task", "Engineering competency assessed", "Max", "Awarded", "Remarks"], [
        ["1", "Build and validate a PGP-style secure mail engine: hybrid encryption, signature and key rings", "8", "", ""], ["2", "S/MIME engineering and comparison with PGP: implementation, trust failure testing and comparison", "9", "", ""],
        ["3", "Secure the IP layer: ESP processing, anti-replay, integrity, tunnel behaviour and attack lab", "10", "", ""], ["4", "Web service security: HTTPS, certificate validation, mutual authentication and hardening", "7", "", ""],
        ["5", "Three defenders, one mailbox: SPF, DKIM and DMARC implementation and evaluation", "7", "", ""], ["6", "Secure mailing at scale: key management, revocation and cost-growth prototype", "9", "", ""], ["", "**TOTAL**", "**50**", "", ""]], [0.4, 3.8, 0.45, 0.8, 1.15], 8.5, align=["c", "l", "c", "c", "l"])
    CAPT("rubII", "Part II – detailed rubric")
    rub2 = [("1.1", "Working sender and receiver; session-key identifier only; protected-message structure; decrypted message, signature result and signer identity; clear failure messages and non-zero exit status", 3),
            ("1.2", "Intermediate values and component sizes; key-to-operation mapping; passed checks; labelled hex/base64 protected-message view and explanation", 2),
            ("1.3", "Predictions and actual comparison for one recipient, five recipients and 10× message size; message-size trend; public-key and symmetric-operation counts; interpretation", 2),
            ("1.4", "Meaningful boundary/tamper test; reason for selecting it; observed behaviour and safe failure handling", 1),
            ("2.1", "S/MIME and PGP normal-case signed/encrypted message from User 1 to User 2; receiving-side validation sequence and signer identity/trust explanation", 2),
            ("2.2", "At least four S/MIME trust-failure cases with prediction, first rejecting check and error output; PGP insufficient-trust warning; cryptographic validity distinguished from identity trust", 3),
            ("2.3", "Evidence-based comparison of public-key operations, message/certificate overhead, verification of an unknown sender and trust dependency (CA vs introducers)", 2),
            ("2.4", "Reasoned choice for 5,000 users across organisations, explicitly based on observed results from 2.1–2.3", 2),
            ("3.A", "ESP-like tunnel-mode processing; encapsulation, SPI/SA lookup, sequence number, encryption/authentication; packet trace and decapsulated content", 2),
            ("3.B", "Predicted and executed replay/reordering tests; exact replay, W/2 delay, >W delay, modified sequence number and meaningful window-edge boundary", 3),
            ("3.C", "Payload tamper, unknown SPI and sequence exhaustion/rekey tests; specific internal logs, safe external response and explanation of information-leak prevention", 2),
            ("3.D", "Transport/tunnel/AH protection-coverage comparison; NAT implications; IKE role, SA establishment, key derivation and refresh/rekey explanation", 3),
            ("4.1", "Working HTTPS service and client; TLS 1.2+ (preferably 1.3); chain, validity and hostname checks; mTLS for protected endpoint; security response headers; protocol/cipher/certificate validation output", 3),
            ("4.2", "Handshake capture identifying ClientHello, ServerHello, certificate, key-exchange parameters and point at which application data is encrypted", 1),
            ("4.3", "Predictions before execution for expired server certificate, IP/hostname mismatch, TLS 1.0-only server and missing client certificate; actual results and failing step", 1),
            ("4.4", "Controlled isolated downgrade/weak-cipher demonstration; corrected secure configuration; connection refusal and explanation of original risk", 1),
            ("4.5", "Reasoned extension for mobile app and third-party laboratories: certificate lifecycle, API-client authentication, authorisation and revocation risks", 1),
            ("5-a", "SPF implementation: correct envelope-sender domain/IP authorisation check and evidence", 1), ("5-b", "DKIM signing/verification: DNS key, signed headers/body integrity and evidence", 1.5),
            ("5-c", "DMARC policy: visible From alignment with SPF/DKIM, policy action and reason", 1.5), ("5-d", "At least four designed messages; predictions, execution results and outcome table (including forwarding, spoofing and modified content)", 1.5),
            ("5-e", "Analysis of whether SPF/DKIM pass can still fail DMARC, legitimate-message failures, and deployment decisions for small company, large organisation and mailing list; distinction from PGP/S/MIME", 1.5),
            ("6.1", "Input, output, objective, constraints and required recipient-key information", 1), ("6.2", "Recipient key-state model; field meanings; new/rollover/expiry/revocation transitions; allow/block states; session-key wrapping and invalid-recipient policy", 2),
            ("6.3", "Working key-store prototype; successful/skipped recipients with exact reasons; final message size and public-key operation count", 2), ("6.4", "Hand-derived result for five recipients including expired and revoked keys; actual decrypt attempts and confidence explanation", 1),
            ("6.5", "Growth experiment for increasing recipient counts; operations, message size and execution-time table; explanation of per-recipient versus one-time work", 1),
            ("6.6", "Reasoned strategy for 200,000 subscribers; identify changed requirement, alternative delivery/key strategy and weakened or changed security properties", 1), ("6.7", "Technical reflection within 150 words, grounded in implementation evidence and explaining why key management remains necessary", 1)]
    TBL(["Criterion", "Evaluation criteria / expected evidence", "Max", "Awarded"], [[a, b, str(c), ""] for a, b, c in rub2], [0.6, 4.9, 0.5, 0.6], 8, align=["c", "l", "c", "c"])
    CAPT("evidII", "Part II – mandatory implementation and submission evidence (evaluator marks Present / Partial / Missing)")
    TBL(["Evidence item", "P", "Part.", "M", "Notes"], [[x, "☐", "☐", "☐", ""] for x in [
        "Source code / scripts and reproducible test inputs", "Expected behaviour / prediction recorded before execution", "Actual output, intermediate values and component-size evidence", "Cryptographic validation logs, certificate details and trust-chain evidence",
        "Packet captures / ESP sequence and replay-window traces, where applicable", "TLS handshake evidence and negotiated protocol/cipher details", "Email headers, DNS records and SPF/DKIM/DMARC evidence", "Attack, tamper, failure, boundary and misconfiguration tests",
        "Interpretation: what worked, what failed, why, and residual risk", "Secure key handling; no hard-coded private keys or logged secrets", "Modular design, meaningful names, robust input handling and fail-closed behaviour", "All experiments confined to own machine / isolated lab using test keys and data"]], [3.9, 0.35, 0.4, 0.35, 1.6], 8.2, align=["l", "c", "c", "c", "l"])
    P("**Overall performance (evaluator):** Task 1 ___/8   Task 2 ___/9   Task 3 ___/10   Task 4 ___/7   Task 5 ___/7   Task 6 ___/9   TOTAL ___/50   Percentage ____ %", 9)
    P("Strengths observed: ______________________________   Technical gaps: ______________________________   Suggestions: ______________________________", 9)
    TBL(["Student signature", "Faculty evaluator signature", "Course coordinator"], [["\n\n", "\n\n", "\n\n"]], [2.2, 2.2, 2.2], 8.5, zebra=False)

    # ------------------------------------------------------------------ guide
    H1("GUIDE – WHERE EACH RUBRIC LINE IS ANSWERED")
    P("Section A maps Part I, Section B maps Part II; Section C states the conventions used; Section D lists honest limits of the evidence so the evaluator can judge the claims at the right scale.", 9.5)
    H2("A. Part I rubric → report location")
    CAPT("mapI", "Part I rubric lines and the subsections that answer them")
    TBL(["Rubric", "Answered in", "Key evidence"], [
        ["1.1–1.3", "Part I, Task 1 (1.1, 1.2, 1.3)", "Deficiency table (11 items); repaired sender/receiver pseudocode; ≤100-word defence"],
        ["2.1–2.5", "Part I, Task 2 (2.1–2.5)", "Requirement model; order hypothesis; PGP pseudocode; numeric desk-check with toy RSA; modified-condition trace"],
        ["3.1–3.5 + coverage", "Part I, Task 3 (3.1–3.5, 3.6 coverage)", "SA state; decision table; ESP pseudocode; W = 4 trace; ICV-before-update argument; architecture/AH/ESP/SA bundle/IKE"],
        ["4.1–4.4", "Part I, Task 4", "Defect, attacker-built certificate, repaired validator (new lines marked), regression table"],
        ["5.1–5.3 + header/spam", "Part I, Task 5 (5.1–5.3, 5.4)", "Web-of-trust algorithm and trust table; chain-validation loop; client-certificate acceptance; header analysis and classifier"],
        ["6-S1…S6", "Part I, Task 6", "Needs/threat table; mechanism choice; state/trust; email + IPsec pseudocode; desk-check; three attacks"]], [1.1, 2.0, 3.5], 8.5)
    H2("B. Part II rubric → report location")
    CAPT("mapII", "Part II rubric lines and the subsections that answer them")
    TBL(["Rubric", "Answered in", "Key evidence"], [
        ["1.1–1.4", "Part II, Task 1", "Protected-message transcript, hex view, 1/5/10× table with predictions, tamper/boundary tests"],
        ["2.1–2.4", "Part II, Task 2", "S/MIME and PGP normal cases, seven S/MIME cases, PGP warning, comparison table, 5,000-user model"],
        ["3.A–3.D", "Part II, Task 3", "Packet trace, eight replay tests with predictions, tamper/SPI/rekey, timing, coverage table, NAT results, IKE log"],
        ["4.1–4.5", "Part II, Task 4", "Service output, handshake capture, four predictions, downgrade lab, mobile/lab extension"],
        ["5", "Part II, Task 5", "SPF/DKIM/DMARC evidence, eight messages, deployment analysis"],
        ["6.1–6.7", "Part II, Task 6", "State model, key-store runs, five-recipient derivation, growth table, 200,000-subscriber strategy, 150-word reflection"]], [1.1, 2.0, 3.5], 8.5)
    H2("C. Conventions")
    P("**Pseudocode standard.** The prescribed SIMATS pseudocode standard was not included in the files supplied with the brief, so the following language-independent convention is used consistently and stated here: each algorithm starts with `ALGORITHM Name(parameters)`, then `INPUT:` and `OUTPUT:` lines; the body sits between `BEGIN` and `END`; assignment is `<-`; comparisons use `=`, `≠`, `<`, `≤`; blocks are `IF … THEN … ELSE … END IF`, `FOR EACH … DO … END FOR`, `WHILE … DO … END WHILE`; every failure path ends in an explicit `RETURN (REJECT, reason)` or `RETURN (DROP, reason)`; comments start with `//`. No programming-language syntax, library names or types are used in Part I.", 9.5)
    P("**Primitive names.** `HASH`, `SIGN(private, data)`, `VERIFY(public, sig, data)`, `RANDOM_KEY(bits)`, `SYM_ENCRYPT/SYM_DECRYPT(key, data)`, `PK_ENCRYPT/PK_DECRYPT(key, data)`, `COMPRESS/DECOMPRESS`, `ICV(key, data)`. Their security assumptions are stated where relevant.", 9.5)
    P("**Predictions.** Wherever the rubric asks for a prediction, the expected result was written down in the experiment program before the run, and the report shows prediction and observation side by side with a match flag generated by the program, so a mismatch would be visible rather than silently edited.", 9.5)
    H2("D. Scale and limits of the evidence")
    BUL(["**Simulated, not production:** the ESP/AH/IKE code is a student simulation of the processing logic (AES-GCM as the combined-mode cipher, HKDF-derived keys, X25519 + ECDSA for the IKE-like exchange). It is not interoperable with a real IPsec stack. DNS for SPF/DKIM/DMARC is a zone file, not live DNS.",
         "**Timings** come from interpreted Python on one machine and are used only to compare designs. **Operation counts, message sizes and accept/reject outcomes** are exact and repeatable.",
         "**Task 6 growth:** 60 distinct RSA-2048 key pairs are reused round-robin as key material for up to 10,000 recipient records (distinct addresses and key IDs). The cost model is unaffected, but the table does not claim 10,000 independent keys.",
         "**Classifier (Part II Task 5 / Part I Task 5):** 12 hand-labelled messages is a demonstration set, not a benchmark; precision/recall figures describe that set only.",
         "**Part I traces** were derived by hand; the Part II engine afterwards reproduced the W = 4 trace line for line, which is reported as a cross-check.",
         "All attack demonstrations use only student-created toy parameters and test data on the local machine, as required by the brief."], 9.5)
