from rb_lib import *


def build():
    H1("PART I – ALGORITHMIC DESIGN THROUGH PSEUDOCODE")
    P("Part I is a design assignment. Everything below is reasoned and traced by hand; the only tools used are the abstract primitives listed in the brief. Where a Part II experiment later confirms a Part I conclusion, the cross-reference is given and is labelled as a cross-check, not as the source of the answer.", 9.5, italic=True)

    # ============================================================= TASK 1
    H2("TASK 1 – SECURITY DESIGN REVIEW (6 marks)", True)
    P("**Scenario.** A company wants to send confidential and authenticated email to a customer. The junior engineer's algorithm is:")
    CODE("ALGORITHM SendSecureEmail\n BEGIN\n   Read message\n   Encrypt message with the key\n   Sign it\n   Send the email\n   RETURN done\n END", title="Given (faulty) pseudocode")
    H3("Task 1.1 – Diagnosis of the design (2 marks)")
    CAPT("t1def", "Eleven security-design deficiencies in the proposed pseudocode")
    TBL(["#", "Deficiency (where in the given text)", "Why another engineer could not reliably implement a secure system as written"], [
        ["1", "**No inputs or outputs declared.** The algorithm has no parameters; “the message”, “the key” and the recipient appear from nowhere.", "Nothing says whose key, whose certificate, or which address is meant. Two engineers will wire different keys in; the design cannot be reviewed because there is nothing to check against."],
        ["2", "**“Encrypt message with the key”** – which key? Symmetric or public? Whose?", "If the sender’s own key is meant, the recipient cannot decrypt; if a shared secret is meant, its distribution is unspecified. The step is not implementable without a guess."],
        ["3", "**No session key.** The only reading that gives confidentiality to a stranger is public-key encryption of the whole message.", "RSA-2048 with OAEP/SHA-256 can encrypt at most 190 bytes; a real email is kilobytes to megabytes, and public-key operations cost orders of magnitude more than symmetric ones (Part II Task 6: 100 recipients × 1 MB = 100 MB if re-encrypted per recipient, versus 1.0 MB hybrid). The standard design is a random one-time symmetric key wrapped by the public key; the pseudocode omits it."],
        ["4", "**“Sign it” – sign what, with which key?** (message, ciphertext or digest; sender’s private key is never named).", "Signing the whole message with a public-key primitive repeats the size/cost problem; signing without naming the key leaves open whether the recipient’s or sender’s key is used. A signature must be over a digest, with the sender’s private key."],
        ["5", "**Order is ambiguous/wrong:** encrypt first, then sign the ciphertext.", "A signature over ciphertext proves only that the signer handled that ciphertext, not that they wrote the plaintext: an attacker can strip the signature and add their own. Signing inside the encryption (sign-then-encrypt) hides the signature and binds it to the plaintext."],
        ["6", "**Nothing is signed about the recipient or time.**", "A recipient can forward a validly signed plaintext to a third party who will believe it was meant for them (surrogate forwarding), and an old message can be replayed. The signed data must include the recipient address and a timestamp/unique ID."],
        ["7", "**No validation of the recipient’s certificate** (expired, revoked, wrong owner, untrusted issuer).", "Encrypting to a key that belongs to an attacker, or to a revoked key, silently destroys confidentiality. Nothing in the pseudocode says where the recipient’s key comes from or why it is trusted."],
        ["8", "**No check of the sender’s own key validity.**", "An expired or revoked signing key produces signatures receivers must reject; the sender would never learn this."],
        ["9", "**No failure handling at all.** No branch for missing key, bad certificate, encryption failure or send failure.", "Every step is assumed to succeed. A fail-open implementation could send in plaintext or unsigned and still “succeed”."],
        ["10", "**`RETURN done` conveys nothing** – the sender learns neither success nor the reason for failure.", "A caller cannot distinguish “queued” from “recipient certificate revoked”, so it cannot retry, alert, or log. Return values must carry a status and reason code."],
        ["11", "**Receiver side is entirely absent**, and no message format (algorithm identifiers, wrapped key, encoding for text-only email transport).", "Without a receiver algorithm there is no specification of what must be verified (signature, signer’s certificate, freshness). Without a format two implementations cannot interoperate."]],
        [0.3, 2.5, 3.8], 8.2, align=["c", "l", "l"])
    H3("Task 1.2 – Repaired design: sender and receiver (3 marks)")
    P("Design decisions used below: (i) hybrid encryption with a fresh session key; (ii) **sign-then-encrypt**, with the signed data containing the message, the recipient address, a timestamp and a unique message ID; (iii) certificates are validated by a separate algorithm, `ValidateCertificate`, specified and repaired in Task 4; (iv) `SYM_ENCRYPT` is assumed to be authenticated encryption (a wrong key or modified ciphertext makes `SYM_DECRYPT` fail); (v) every failure path returns a reason and no partial output.", 9.5)
    CODE("""ALGORITHM SendSecureEmail(Msg, SenderPrivKey, SenderCert, RecipientCert, RecipientAddr, TrustedRoots, CRLs, Now)
 INPUT:   Msg            - plaintext to protect
          SenderPrivKey  - sender's private signing key
          SenderCert     - sender's certificate (carries sender's public key)
          RecipientCert  - certificate that should belong to RecipientAddr
          RecipientAddr  - address of the intended recipient
          TrustedRoots, CRLs, Now - local trust anchors, revocation lists, current time
 OUTPUT:  (OK, Envelope)  or  (ERROR, reason)
 BEGIN
   IF Msg is empty OR SenderPrivKey = NULL OR RecipientCert = NULL THEN RETURN (ERROR, BAD_INPUT) END IF
   IF NOT (SenderCert.notBefore <= Now AND Now <= SenderCert.notAfter) THEN RETURN (ERROR, OWN_KEY_EXPIRED) END IF
   r <- ValidateCertificate(RecipientCert, RecipientAddr, "keyEncipherment", TrustedRoots, CRLs, Now)   // Task 4.3
   IF r <> OK THEN RETURN (ERROR, RECIPIENT_CERT_ + r) END IF                                            // never encrypt to an unvalidated key
   stamp  <- Now
   msgID  <- RANDOM_KEY(128)                                   // unique message identifier
   signed <- Msg || RecipientAddr || stamp || msgID            // what the signature will cover
   digest <- HASH(signed)
   sig    <- SIGN(SenderPrivKey, digest)                       // 1. sign the DIGEST with the sender's PRIVATE key
   block  <- (Msg, RecipientAddr, stamp, msgID, sig, SenderCert)
   Ks     <- RANDOM_KEY(256)                                   // 2. fresh one-time session key
   C      <- SYM_ENCRYPT(Ks, block)                            // 3. encrypt the whole signed block (signature is hidden)
   WK     <- PK_ENCRYPT(RecipientCert.publicKey, Ks)           // 4. wrap Ks for the recipient only
   Envelope <- ENCODE(algorithmIDs, WK, C)                     // 5. text-safe encoding for email
   ERASE(Ks)
   RETURN (OK, Envelope)
 END""", title="Sender side")
    CODE("""ALGORITHM ReceiveSecureEmail(Envelope, MyPrivKey, MyAddr, FromAddr, TrustedRoots, CRLs, SeenIDs, Now, MaxAge)
 INPUT:   Envelope - received text;  MyPrivKey, MyAddr - my decryption key and address
          FromAddr - address in the visible From header;  SeenIDs - message IDs already accepted
 OUTPUT:  (ACCEPT, Msg, signerIdentity)  or  (REJECT, reason)
 BEGIN
   (WK, C) <- DECODE(Envelope)
   IF decoding fails THEN RETURN (REJECT, MALFORMED) END IF
   Ks <- PK_DECRYPT(MyPrivKey, WK)
   IF Ks = FAILURE THEN RETURN (REJECT, CANNOT_UNWRAP_KEY) END IF
   block <- SYM_DECRYPT(Ks, C)
   ERASE(Ks)
   IF block = FAILURE THEN RETURN (REJECT, DECRYPTION_OR_INTEGRITY_FAILURE) END IF
   (Msg, RcptAddr, stamp, msgID, sig, SenderCert) <- PARSE(block)
   IF RcptAddr <> MyAddr THEN RETURN (REJECT, NOT_ADDRESSED_TO_ME) END IF          // stops surrogate forwarding
   r <- ValidateCertificate(SenderCert, FromAddr, "digitalSignature", TrustedRoots, CRLs, Now)
   IF r <> OK THEN RETURN (REJECT, SENDER_CERT_ + r) END IF                         // trust BEFORE trusting the key
   digest <- HASH(Msg || RcptAddr || stamp || msgID)
   IF VERIFY(SenderCert.publicKey, digest, sig) <> TRUE THEN RETURN (REJECT, BAD_SIGNATURE) END IF
   IF Now - stamp > MaxAge OR stamp > Now + MaxAge OR msgID IN SeenIDs THEN RETURN (REJECT, STALE_OR_REPLAYED) END IF
   ADD msgID TO SeenIDs
   RETURN (ACCEPT, Msg, SenderCert.subject)
 END""", title="Receiver side")
    H3("Task 1.3 – Design defence (≤ 100 words) (1 mark)")
    d13 = ("The rewritten text is pseudocode because it fixes the order of abstract operations (SIGN, SYM_ENCRYPT, PK_ENCRYPT), names every input and output, "
           "and states each decision and its failure result, yet uses no language syntax, library calls, types or memory handling. "
           "Unlike informal English (“sign it”), each line has one unambiguous meaning another engineer can implement in any language. "
           "Unlike programming code, primitives stay abstract, so the design can be checked against its security properties before any implementation exists.")
    n13 = len(d13.split()); assert n13 <= 100, n13
    P(d13); P(f"__({n13} words)__", 8.5, align="l")
    BOX("Rubric check – Task 1", ["1.1 ✔ eleven deficiencies, each with the reason it blocks a reliable implementation.   1.2 ✔ sender and receiver with explicit order and checks.   1.3 ✔ " + f"{n13}-word defence."])

    # ============================================================= TASK 2
    H2("TASK 2 – FROM SECURITY REQUIREMENT TO PGP PSEUDOCODE (8 marks)", True)
    P("**Scenario.** A legal firm sends case documents by email. Each message needs authentication, integrity, confidentiality and compression. There is no central CA; participants exchange public keys directly.")
    H3("Task 2.1 – Model the requirement (2 marks)")
    CAPT("t2req", "Requirement model for PGP-style protection")
    TBL(["Element", "Model"], [
        ["**Input**", "Plaintext document M (KB to MB, may be compressible); sender’s private key KRa and public key KUa; recipient’s public key KUb taken from the sender’s key ring; the key ring (public keys, key IDs, validity information); the current time."],
        ["**Output (what is actually transmitted)**", "One text-safe message `RADIX64( KeyID(KUb) ‖ PK_ENCRYPT(KUb, Ks) ‖ SYM_ENCRYPT(Ks, COMPRESS( KeyID(KUa) ‖ timestamp ‖ SIGN(KRa, HASH(M)) ‖ M )) )`. Neither M, the signature, nor Ks appears in clear."],
        ["**Security objectives**", "**Authentication** of the sender (digital signature); **integrity** of M (signed digest); **confidentiality** of M and the signature (symmetric encryption under a one-time key, key sealed for the recipient); **compression** to reduce size; **transport-safety** (radix-64 survives 7-bit mail systems)."],
        ["**Constraints**", "Message size is unbounded, whereas RSA can seal only a few hundred bytes → public-key operations must be applied only to small values (a digest and a session key). Public-key operations are expensive → count them (here: 1 signing + 1 wrap per recipient). Recipient has a key ring → keys are looked up by key ID. No CA → the validity of KUb and KUa rests on the web of trust (Task 5.1)."],
        ["**Sender’s decisions**", "What to sign: the **digest of M** (not the ciphertext). What to compress: **signature ‖ M** (after signing). What to encrypt with which key: the compressed block with the **session key Ks**; Ks itself with **KUb**. Whether KUb is valid enough to use (web-of-trust result)."],
        ["**Receiver needs**", "Its own key ID inside the message (to find the right wrapped key); the wrapped session key; the ciphertext; the signer’s key ID (to fetch KUa); the signature and timestamp; algorithm identifiers; a way to decide whether KUa is valid."]],
        [1.6, 5.0], 8.4)
    H3("Task 2.2 – Design hypothesis (1 mark)")
    BOX("Design rule", ["**Sign the message digest first, then compress (signature ‖ message), then encrypt the compressed block with a fresh random session key Ks, and finally encrypt Ks alone with the recipient’s public key.**"], "EEF3FB", "2B5C8A")
    P("**Justification.** (i) __Sign before compress:__ the signature must verify against the original M. Compressors are not guaranteed to produce identical output across versions or settings, so a signature made over compressed bytes could fail on re-verification; signing M also lets the signed plaintext be stored and re-verified later without the encryption. (ii) __Compress before encrypt:__ ciphertext is statistically random and cannot be compressed afterwards, and compressing after encryption would save nothing. (iii) __Sign before encrypt:__ the signature is hidden inside the ciphertext, so an outsider cannot strip it or substitute their own. (iv) __Session key:__ public-key operations touch only the 32-byte Ks and the digest, never the bulk data.")
    H3("Task 2.3 – Pseudocode: sender and receiver (3 marks)")
    CODE("""ALGORITHM PGPSend(M, KRa, KUa, KUbID, KeyRing, Now)
 INPUT:  M - message;  KRa, KUa - sender's key pair;  KUbID - key ID of the recipient;  KeyRing;  Now
 OUTPUT: (OK, R) with R the radix-64 text, or (ERROR, reason)
 BEGIN
   KUb <- LOOKUP(KeyRing, KUbID)
   IF KUb = NULL THEN RETURN (ERROR, RECIPIENT_KEY_NOT_IN_RING) END IF
   IF KeyValidity(KUb, KeyRing, Now) <> VALID THEN RETURN (ERROR, RECIPIENT_KEY_NOT_VALID) END IF   // Task 5.1
   h     <- HASH(M)                                   // message digest
   S     <- SIGN(KRa, h)                              // signature generation
   block <- KeyID(KUa) || Now || S || M               // signature header + message
   Z     <- COMPRESS(block)                           // compression AFTER signing
   Ks    <- RANDOM_KEY(256)                           // session-key generation
   C     <- SYM_ENCRYPT(Ks, Z)                        // symmetric encryption of the payload
   WK    <- PK_ENCRYPT(KUb, Ks)                       // session key sealed for the recipient
   R     <- RADIX64( KUbID || WK || C )               // encoding for email transport
   ERASE(Ks)
   RETURN (OK, R)
 END""", title="Sender")
    CODE("""ALGORITHM PGPReceive(R, KRb, MyKeyID, KeyRing, Now)
 INPUT:  R - received text;  KRb - my private key;  MyKeyID;  KeyRing;  Now
 OUTPUT: (ACCEPT, M, signerID, trust)  or  (REJECT, reason)
 BEGIN
   (KeyIDinMsg, WK, C) <- RADIX64_DECODE(R)
   IF decoding fails THEN RETURN (REJECT, MALFORMED) END IF
   IF KeyIDinMsg <> MyKeyID THEN RETURN (REJECT, NOT_A_RECIPIENT) END IF
   Ks <- PK_DECRYPT(KRb, WK)                          // session-key recovery
   IF Ks = FAILURE THEN RETURN (REJECT, KEY_UNWRAP_FAILED) END IF
   Z  <- SYM_DECRYPT(Ks, C);  ERASE(Ks)               // payload decryption
   IF Z = FAILURE THEN RETURN (REJECT, DECRYPTION_FAILED) END IF
   block <- DECOMPRESS(Z)
   IF block = FAILURE THEN RETURN (REJECT, DECOMPRESSION_FAILED) END IF
   (signerID, stamp, S, M) <- PARSE(block)
   KUa <- LOOKUP(KeyRing, signerID)
   IF KUa = NULL THEN RETURN (REJECT, UNKNOWN_SENDER_KEY) END IF
   IF KUa is revoked OR expired at Now THEN RETURN (REJECT, SENDER_KEY_NOT_USABLE) END IF
   h1 <- HASH(M)                                      // recompute digest of what was received
   h2 <- recovered digest from S using KUa            // i.e. VERIFY(KUa, h1, S)
   IF VERIFY(KUa, h1, S) <> TRUE THEN RETURN (REJECT, BAD_SIGNATURE) END IF   // the action on verification failure: discard, report reason
   v <- KeyValidity(KUa, KeyRing, Now)
   IF v = VALID THEN RETURN (ACCEPT, M, signerID, TRUSTED)
   ELSE RETURN (ACCEPT, M, signerID, UNVALIDATED_WARNING) END IF   // signature genuine but the signer's key is not validated
 END""", title="Receiver")
    H3("Task 2.4 – Desk-check with “MEET AT 9” (1 mark)")
    M = b"MEET AT 9"; h = sum(M) % 100; na, ea, da, nb, eb, db = 3233, 17, 2753, 2773, 17, 157; S = pow(h, da, na); Ks = 42; WK = pow(Ks, eb, nb)
    blk = bytes([S >> 8, S & 255]) + M; C = bytes(b ^ Ks for b in blk)
    assert pow(WK, db, nb) == Ks and pow(S, ea, na) == h and bytes(b ^ Ks for b in C)[2:] == M
    P("**Toy cryptography (symbolic in the brief, numeric here so every value can be checked).** Alice’s key: p = 61, q = 53, n<sub>a</sub> = 3233, e<sub>a</sub> = 17 (KUa), d<sub>a</sub> = 2753 (KRa); Bob’s key: p = 47, q = 59, n<sub>b</sub> = 2773, e<sub>b</sub> = 17 (KUb), d<sub>b</sub> = 157 (KRb); check: 17×2753 ≡ 1 (mod 3120) and 17×157 ≡ 1 (mod 2668). Toy digest `H(M) = (sum of ASCII codes) mod 100`; toy session cipher `SYM(Ks, x) = x XOR Ks` byte-wise with **Ks = 42**; toy compression `Z(x) = x` (the 11-byte block is too short to compress; Part II Task 1 shows a real compressor __expands__ a 9-byte message from 267 to 278 bytes).".replace("<sub>", "").replace("</sub>", ""), 9)
    rows = [["S1", "M", "“MEET AT 9” = [77,69,69,84,32,65,84,32,57]", "input"],
            ["S2", "h = H(M)", f"sum = {sum(M)};  {sum(M)} mod 100 = **{h}**", "digest"],
            ["S3", "S = SIGN(KRa, h) = h^d mod n", f"{h}^2753 mod 3233 = **{S}**  (= 0x{S:04X} → bytes [{S>>8}, {S&255}])", "signature"],
            ["S4", "block = S ‖ M", f"[{S>>8}, {S&255}, 77,69,69,84,32,65,84,32,57]  (11 bytes)", "KeyID/time omitted for brevity"],
            ["S5", "Z = COMPRESS(block)", "identical to block (toy)", "compression after signing"],
            ["S6", "C = SYM(Ks, Z)", "each byte XOR 42 → " + str(list(C)), "payload encrypted"],
            ["S7", "WK = PK_ENCRYPT(KUb, Ks) = Ks^e mod n", f"42^17 mod 2773 = **{WK}**", "only Bob can open it"],
            ["S8", "R = RADIX64(KeyID(KUb) ‖ WK ‖ C)", "transmitted: (keyID<sub>b</sub>, 1466, C)".replace("<sub>", "").replace("</sub>", ""), "email body"],
            ["R1", "decode, keyID check", "keyID = MyKeyID → continue", "I am a recipient"],
            ["R2", "Ks = PK_DECRYPT(KRb, WK) = WK^d mod n", f"{WK}^157 mod 2773 = **42**", "session key recovered"],
            ["R3", "Z = SYM_DECRYPT(Ks, C)", f"XOR 42 → [{S>>8}, {S&255}, 77,69,69,84,32,65,84,32,57]", "decrypted"],
            ["R4", "block = DECOMPRESS(Z)", "same", "decompressed"],
            ["R5", "split", f"S = {S};  M = “MEET AT 9”", "signature separated"],
            ["R6", "h1 = H(M)", f"**{h}**", "digest recomputed"],
            ["R7", "h2 = S^e mod n  (VERIFY)", f"{S}^17 mod 3233 = **{pow(S, ea, na)}**", "digest recovered from signature"],
            ["R8", "h1 = h2 ?", f"{h} = {pow(S, ea, na)} → TRUE", "**ACCEPT**, M = “MEET AT 9”"]]
    CAPT("t2trace", "Desk-check: intermediate values on the sender side (S1–S8) and receiver side (R1–R8)")
    TBL(["Step", "Operation", "Value", "Note"], rows, [0.45, 2.0, 3.3, 1.2], 8.2)
    H3("Task 2.5 – Challenge the design (1 mark)")
    Ct = bytearray(C); Ct[-1] ^= 1; b3 = bytes(b ^ Ks for b in Ct); h1 = sum(b3[2:]) % 100
    P(f"**Modified condition:** an attacker flips the lowest bit of the **last ciphertext byte** (C = …{C[-1]} → {Ct[-1]}).")
    P("**Prediction (written before tracing).** Steps R1–R2 are unaffected (the wrapped key is untouched). R3 will succeed – the toy cipher has no integrity check – but yields M′ with the last character changed (0x39 ‘9’ → 0x38 ‘8’). The decision expected to change is **R8, the digest comparison h1 = h2**: h1 will be computed from M′ and will differ from h2 recovered from the untouched signature. Expected result: REJECT, BAD_SIGNATURE.")
    P(f"**Trace of the relevant steps.** R3: byte {Ct[-1]} XOR 42 = {Ct[-1]^42} → M′ = “MEET AT 8”. R6: h1 = (569 − 1) mod 100 = **{h1}**. R7: h2 = S^e mod n = **{pow(S, ea, na)}** (unchanged). R8: {h1} ≠ {pow(S, ea, na)} → `RETURN (REJECT, BAD_SIGNATURE)`.")
    P("**Prediction correct.** The attack is caught, but only at the __last__ step. Consequence for the design: if `SYM_ENCRYPT` is authenticated encryption (as assumed in Task 1 and used in the Part II engine), R3 itself fails with DECRYPTION_FAILED and the signature check is a second layer; with an unauthenticated cipher the signature is the only integrity barrier, and the receiver has already spent decryption and decompression effort on a tampered message. A second modified condition (**two recipients**) changes only the wrapping step: S7 is repeated with KUc, producing a second wrapped key, while C and the signature are reused – public-key operations rise from 2 to 3 and nothing else grows (measured in Part II Task 1: +266 bytes per recipient).")
    BOX("Rubric check – Task 2", ["2.1 ✔ model table.  2.2 ✔ one-sentence rule + justification.  2.3 ✔ sender/receiver pseudocode with failure handling.  2.4 ✔ numeric desk-check.  2.5 ✔ prediction, affected decision (R8), trace and verdict."])

    # ============================================================= TASK 3
    H2("TASK 3 – FROM STATE TO EXECUTABLE LOGIC: IPsec ESP ANTI-REPLAY (9 marks)", True)
    H3("Task 3.1 – State for one Security Association (1 mark)")
    CAPT("t3state", "Receiver state for one inbound SA")
    TBL(["Element", "Definition (exactly what it represents)"], [
        ["`SPI`", "32-bit identifier carried in every ESP packet; together with destination and protocol it selects this SA in the SA database."],
        ["`W`", "Window size (number of sequence numbers tracked), fixed when the SA is created; here W = 32 in the experiments and W = 4 in the desk-check."],
        ["`Highest`", "The **largest sequence number of any packet that passed the ICV check and was accepted** on this SA. 0 means nothing accepted yet (sequence numbers start at 1; 0 is never valid)."],
        ["`Window`", "A W-bit bitmap. **Bit i (i = 0 … W−1) is 1 if and only if sequence number `Highest − i` has been received and accepted.** Bit 0 therefore always represents `Highest` itself (1 once any packet has been accepted). The window covers the sequence numbers `Highest − W + 1 … Highest`."],
        ["`keys, lifetime`", "Integrity (ICV) key and, for ESP, the encryption key; byte/time/sequence lifetime that triggers re-keying. Replay state belongs to one SA only – a new SA starts with `Highest = 0` and an empty window."]], [1.1, 5.5], 8.5)
    H3("Task 3.2 – The decision rule (2 marks)")
    P("For a packet with sequence number `s` that has **already passed the ICV check**, define `d = Highest − s`.")
    CAPT("t3rule", "Decision rule and the meaning of each condition")
    TBL(["Condition", "Meaning", "Decision", "State change"], [
        ["`s = 0`", "Sequence 0 is never used by a conforming sender.", "DROP (SEQ_ZERO)", "none"],
        ["`s > Highest`", "A **new** packet beyond everything seen so far. Because it is authentic and ahead of the window, it cannot be a replay of an earlier packet.", "ACCEPT (NEW)", "Slide: `Window ← (Window << (s−Highest)) OR 1` (bits shifted out are forgotten); `Highest ← s`. If the jump is ≥ W the window becomes just bit 0."],
        ["`s ≤ Highest` and `d < W` and bit d = 0", "Inside the window and **not yet received**: a packet that was reordered/delayed by the network. Accepting it once is correct.", "ACCEPT (IN_WINDOW_UNSEEN)", "Set bit d: `Window ← Window OR (1 << d)`; `Highest` unchanged."],
        ["`s ≤ Highest` and `d < W` and bit d = 1", "Inside the window and **already received**: a duplicate (replay or network duplicate).", "DROP (REPLAY_DUPLICATE)", "none"],
        ["`s ≤ Highest` and `d ≥ W`", "**Older than the window.** The receiver no longer remembers whether it was seen, so to guarantee “at most once” it must refuse it – even if it is genuine but very late.", "DROP (REPLAY_TOO_OLD)", "none"]], [1.6, 2.6, 1.2, 1.5], 8.2)
    P("**Where the window may advance.** Only **after** the ICV check succeeds and only on ACCEPT. The ICV (integrity check value) is the only evidence the packet came from the SA’s peer; sequence numbers are plain integers an attacker can write at will. Reading `Highest`/`Window` before the ICV is harmless (it can be used to discard obvious duplicates cheaply), but __writing__ them before the ICV is verified lets an unauthenticated packet change the state (Task 3.5).")
    H3("Task 3.3 – Pseudocode (4 marks)")
    CODE("""ALGORITHM InitSA(spi, W, intKey, encKey, lifetime)
 OUTPUT: SA record
 BEGIN
   SA.SPI <- spi;  SA.W <- W;  SA.Highest <- 0;  SA.Window <- 0      // W-bit bitmap of zeros
   SA.intKey <- intKey;  SA.encKey <- encKey;  SA.lifetime <- lifetime
   ADD SA TO SAD INDEXED BY spi
   RETURN SA
 END

ALGORITHM ProcessInboundESP(Packet, SAD)
 INPUT:  Packet - received ESP packet (SPI, Seq, payload, ICV);  SAD - SA database
 OUTPUT: (ACCEPT, reason, innerPacket)  or  (DROP, reason)       // reason is written to the INTERNAL log; nothing is sent to the peer
 BEGIN
   SA <- LOOKUP(SAD, Packet.SPI)                                  // 1. SA lookup
   IF SA = NULL THEN LOG("unknown SPI"); RETURN (DROP, UNKNOWN_SPI) END IF
   IF SA expired (time, bytes or sequence lifetime) THEN LOG("SA expired"); RETURN (DROP, SA_EXPIRED) END IF
   expected <- ICV(SA.intKey, Packet.SPI || Packet.Seq || Packet.payload)      // 2. integrity FIRST
   IF NOT CONSTANT_TIME_EQUAL(expected, Packet.ICV) THEN LOG("ICV failure"); RETURN (DROP, ICV_FAIL) END IF
   s <- Packet.Seq                                                 // 3. replay check, on an AUTHENTIC packet only
   IF s = 0 THEN RETURN (DROP, SEQ_ZERO) END IF
   IF s > SA.Highest THEN
        shift <- s - SA.Highest
        IF shift >= SA.W THEN SA.Window <- 1 ELSE SA.Window <- ((SA.Window << shift) OR 1) AND (2^SA.W - 1) END IF
        SA.Highest <- s;  reason <- NEW                            // 4. state update only now
   ELSE
        d <- SA.Highest - s
        IF d >= SA.W THEN RETURN (DROP, REPLAY_TOO_OLD) END IF
        IF bit d of SA.Window = 1 THEN RETURN (DROP, REPLAY_DUPLICATE) END IF
        set bit d of SA.Window;  reason <- IN_WINDOW_UNSEEN
   END IF
   inner <- DECRYPT_AND_DECAPSULATE(SA.encKey, Packet)             // 5. only now is the payload processed
   RETURN (ACCEPT, reason, inner)
 END""")
    P("Every DROP path returns a __reason__ (for the internal log and for tests); none of them changes `Highest` or `Window`. Externally the gateway stays silent for every drop, so the reason is not an oracle for the attacker (measured in Part II Task 3.C).", 9.5)
    H3("Task 3.4 – Desk-check, W = 4 (1 mark)")
    w4 = J("t3")["W4"]
    P("Rule used for the window: after an accepted packet the window covers `Highest−3 … Highest`; entries show the sequence numbers currently marked as received. Hand derivation, then (right-hand column) the same table as reproduced later by the Part II engine – the two agree on every line (cross-check).", 9.5)
    hand = ["1 > 0 → NEW", "2 > 1 → NEW", "5 > 2 → NEW; shift 3; window 2..5, 1 slides out", "d = 5−3 = 2 < 4, bit unset → IN_WINDOW_UNSEEN", "d = 3, bit set → REPLAY_DUPLICATE", "9 > 5 → NEW; shift 4 ≥ W, window = {9}", "d = 9−4 = 5 ≥ 4 → REPLAY_TOO_OLD", "ICV invalid → DROP before any state is touched", "d = 9−7 = 2 < 4, bit unset → IN_WINDOW_UNSEEN"]
    CAPT("t3w4", "Trace of Highest and Window for W = 4")
    TBL(["#", "Seq", "ICV", "Reasoning (hand)", "Decision", "Highest", "Window (received)"], [[str(e["order"]), str(e["seq"]), e["icv"], hand[i], e["decision"] + " – " + e["reason"], str(e["highest"]), "{" + ", ".join(str(x) for x in sorted(e["window"])) + "}"] for i, e in enumerate(w4)],
        [0.3, 0.4, 0.5, 2.3, 1.45, 0.55, 1.1], 7.8, align=["c", "c", "c", "l", "l", "c", "l"])
    FIG("p3_window", 6.4, "Window state after each packet of Task 3.4 (green = received; yellow = inside window, not received).")
    P("**Observation.** Packet 4 (seq 3) is accepted although 5 has already arrived – reordering is tolerated inside the window. Packet 7 (seq 4) is genuine but dropped because the jump to 9 pushed it out of the window: the price of bounded memory. Packet 8 (invalid ICV, seq 7) is dropped __without__ marking 7 as received, so the genuine seq 7 in packet 9 is still accepted – the evidence that the ICV check protects the state.")
    H3("Task 3.5 – Why the ICV must be verified before the window is updated (1 mark)")
    P("In `ProcessInboundESP` the ICV test (step 2) precedes every write to `SA.Highest` and `SA.Window` (step 4). Suppose the order were reversed. An attacker who cannot forge ICVs can still send a packet with the **right SPI and a forged sequence number such as 4,000,000,000** and any garbage ICV. The gateway would first ‘accept’ the number, setting `Highest = 4,000,000,000`, and only afterwards discover the ICV is wrong and drop the packet – but the state change has already happened. Every genuine packet that follows (sequence numbers near 5,000) now satisfies `d ≥ W` and is dropped as REPLAY_TOO_OLD: **a denial of service by a single unauthenticated packet** (a ‘window-slam’). A milder variant marks genuine future sequence numbers as received so the real packets are later rejected as duplicates. With the ICV first, such a packet fails at step 2 and the state stays untouched – shown by trace row 8 above and by Part II tests iv and iv-b (modified sequence field: ICV_FAIL, window unchanged). The same reasoning explains why the ICV covers the SPI and sequence number: changing the sequence field of a captured packet invalidates its ICV.")

    # ----------------------------------------------------- IPsec coverage
    H2("Task 3 coverage block – the full IPsec syllabus (within the Task 3 marks)")
    H3("3.6.1 Overview and architecture")
    CAPT("t3svc", "IPsec security services and how AH and ESP deliver them")
    TBL(["Service", "AH", "ESP (encryption + integrity)", "Mechanism"], [
        ["Access control", "✔", "✔", "SPD selects which traffic must be protected; no SA ⇒ no accepted traffic"],
        ["Connectionless integrity", "✔ (header + payload)", "✔ (ESP header, payload, trailer – not outer IP header)", "ICV per packet"],
        ["Data-origin authentication", "✔", "✔", "Keys known only to the two SA peers"],
        ["Anti-replay", "✔", "✔", "Sequence number + window (Task 3.1–3.3)"],
        ["Confidentiality", "✘", "✔", "ESP cipher"],
        ["Limited traffic-flow confidentiality", "✘", "✔ in tunnel mode (inner addresses hidden), padding", "Tunnel mode + padding"]], [1.7, 1.2, 2.0, 1.7], 8.2)
    P("**Architecture.** An IPsec implementation consists of the **Security Policy Database (SPD)** (what to protect, with which protocol and mode), the **Security Association Database (SAD)** (live SAs with keys, SPI, sequence/replay state, lifetimes) and an automatic key-management protocol, **IKE**, that creates SAs. **Hosts** apply IPsec to their own traffic; **security gateways** apply it on behalf of the networks behind them. AH is IP protocol 51 and ESP is IP protocol 50. **Transport mode** keeps the original IP header and protects only the payload (host-to-host); **tunnel mode** wraps the __entire original packet__ in a new outer IP header (gateway-to-gateway or host-to-gateway) – the mode the hospital branch link needs. Each SA is **unidirectional**, so a two-way link needs two SAs.")
    H3("3.6.2 ESP – confidentiality, integrity and anti-replay; protected and unprotected portions")
    FIG("t3_formats", 6.3, "Protection coverage of ESP transport, ESP tunnel and AH transport packets (the field table is generated by the Part II program).", "fig_formats")
    P("**ESP processing.** The sender increments the SA’s sequence counter, pads the plaintext (inner packet in tunnel mode, upper-layer payload in transport mode) to a block boundary, appends pad length and next-header, encrypts, and computes the ICV over `SPI ‖ Seq ‖ IV ‖ ciphertext`. In transport mode the **original IP header is neither encrypted nor authenticated**; in tunnel mode the **new outer IP header** is neither encrypted nor authenticated, but the entire original packet – including its addresses – is encrypted and authenticated. Replay protection applies to the sequence number as in Task 3.3.")
    H3("3.6.3 AH – authenticated fields, NAT limitation, comparison with ESP")
    P("AH computes its ICV over the **immutable** IP fields (version/IHL, total length, protocol, **source and destination addresses**), the AH header with the ICV field zeroed, and the payload. **Mutable fields** that routers legitimately change in flight – TOS/DSCP, flags/fragment offset, **TTL** and the header checksum – are set to zero for the calculation so they do not invalidate the ICV. **NAT limitation:** NAT rewrites the source (or destination) address, which AH has authenticated, so the ICV fails and AH cannot traverse NAT at all (measured in Part II Task 3.D).")
    CAPT("t3ahesp", "AH compared with ESP")
    TBL(["Aspect", "AH", "ESP"], [["Confidentiality", "None", "Yes"], ["Integrity coverage", "Payload and immutable IP header fields (incl. addresses)", "ESP header, payload, trailer; **not** the outer IP header"],
        ["Behaviour behind NAT", "Breaks (address is covered)", "Works in tunnel mode (ICV excludes the outer header); transport mode breaks upper-layer checksums; NAT-T (UDP 4500) is used in practice"],
        ["When it still makes sense", "Authentication-only where confidentiality is not wanted and no NAT exists", "Almost all deployments (with authenticated encryption, AH is largely redundant)"]], [1.6, 2.4, 2.6], 8.2)
    H3("3.6.4 Combining Security Associations – a small example with a trace")
    P("**Why combine?** One SA offers one protocol in one mode between one pair of endpoints. The hospital needs two different guarantees at two different places: (a) __host-to-host authentication__ between the lab workstation and the branch server that survives even a compromised gateway, and (b) __confidentiality across the public network__ between the two gateways. These cannot be delivered by a single SA, so an **SA bundle** is used: **SA1 = AH, transport mode, host A → host B** (inner), carried inside **SA2 = ESP, tunnel mode, gateway A → gateway B** (outer).")
    FIG("t3_bundle", 6.4, "SA bundle: AH (transport) applied first by the host, ESP (tunnel) applied second by the gateway.", "fig_bundle")
    CAPT("t3bundle", "Packet trace through the bundle (from the Part II simulation, cross-check)")
    b = J("t3")["bundle"]
    TBL(["Step", "Where", "Operation", "Packet after the step"], [
        ["1", "Host A", "Build IP/UDP packet 10.1.0.5 → 10.2.0.9 carrying the lab result", f"{b['sizes']['original']} bytes"],
        ["2", "Host A", f"Apply SA1 (AH transport, SPI {b['spi_ah']}): ICV over immutable header fields + payload", f"{b['sizes']['after_AH']} bytes (+24, AH header with 12-byte ICV)"],
        ["3", "Gateway A", f"Apply SA2 (ESP tunnel, SPI {b['spi_esp']}): encapsulate, encrypt, ICV, new outer header 192.0.2.1 → 198.51.100.1", f"{b['sizes']['after_ESP']} bytes (+55)"],
        ["4", "Gateway B", "SA2 lookup by SPI → ICV valid → replay check: NEW (seq 1) → decrypt and decapsulate", f"{b['sizes']['after_AH']} bytes (inner AH packet recovered); decision: {b['gw_decision']['decision']} – {b['gw_decision']['reason']}"],
        ["5", "Host B", "SA1 lookup, AH ICV verification over the inner packet", f"ICV valid = {b['ah_ok']}; payload “{b['payload']}” delivered"]], [0.45, 0.9, 3.5, 1.75], 8.2)
    P("Processing order on receipt is the **reverse of application order**: the outer SA (ESP) is processed first, the inner SA (AH) last. Each SA has its own SPI, keys and replay window; a packet failing at the outer layer never reaches the inner one.")
    H3("3.6.5 Key management – IKE")
    FIG("t3_ike", 6.3, "IKE-style exchange, authentication and re-keying (message flow of the Part II simulation).", "fig_ike")
    BUL(["**Negotiate and establish.** IKE_SA_INIT exchanges Diffie–Hellman public values and nonces; both sides derive a shared secret and from it a seed (`SKEYSEED`) from which IKE-SA keys are derived. IKE_AUTH, encrypted under those keys, authenticates the peers (signatures over the exchanged values using certificates, or pre-shared keys) and creates the first **child SA**: SPIs, algorithms and traffic selectors are agreed and per-direction encryption/integrity keys are derived from the seed with a key-derivation function.",
         "**Why authenticated DH.** Unauthenticated Diffie–Hellman is open to man-in-the-middle (Q4 in the CO2 assignment); IKE signs the transcript so the exchanged values are bound to the peers’ identities.",
         "**Refresh / re-key.** A child SA has a lifetime (time, bytes, or sequence-number space – the 32-bit counter must never wrap). Before it ends, CREATE_CHILD_SA runs a **new DH exchange** (perfect forward secrecy) and nonces and installs a new SA with a new SPI, fresh keys and a fresh replay window (`Highest = 0`). The old SA stays alive briefly to receive packets still in flight and is then deleted.",
         "**Expiry without re-key.** When an SA expires its SPI disappears from the SAD; late packets are dropped as UNKNOWN_SPI (Part II Task 3.C). The sender must never reuse a sequence number under the same key, so on exhaustion it must stop sending and re-key."], 9.3)
    BOX("Rubric check – Task 3", ["3.1 ✔ state with exact meaning of Highest/Window.  3.2 ✔ five-condition decision rule with meaning and the advance-point rule.  3.3 ✔ init, SA lookup, ICV, replay check, update-only-when-appropriate, reason on every drop.  3.4 ✔ nine-row W = 4 trace.  3.5 ✔ window-slam attack tied to pseudocode steps 2 and 4.  Coverage ✔ architecture, AH, ESP, SA bundle with trace, IKE."])
