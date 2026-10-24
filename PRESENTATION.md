# Presentation Notes - Digital Signature & Document Verification System

Team: Nikhil Bakolia (PRN 25030422079), Aanya Arney (PRN 25030422003). Submitted to: Veena Madaan.

## Slides (11)

**1. Title** - Digital Signature & Document Verification System. Introduce team and course.

**2. Problem** - Files can be edited silently; receiver cannot confirm origin or integrity; checksums alone can be recomputed by an attacker. *Say:* we need proof of both "unchanged" and "who signed".

**3. Core ideas** - Hash (fingerprint of data); key pair (private signs, public verifies); signature = hash signed with private key. *Say:* explain with the live hash demo on the Learn page.

**4. Objectives** - generate keys, sign, verify, explain results, store no secrets.

**5. Architecture** - Browser pages → FastAPI → crypto service → SQLite. One server serves everything.

**6. Signing flow** - document → SHA-256 → message {hash, time, key fingerprint} → RSA-PSS sign → .sig.json.

**7. Verification flow** - three checks: integrity, key match, authenticity. VALID only if all pass.

**8. Security design** - standard library crypto; private keys never stored; passphrase-encrypted key files; validation; ORM; safe errors; rate limit.

**9. Live demo** - sign sample, verify VALID, verify tampered (Rs. 500 → 5000) INVALID, wrong key INVALID.

**10. Testing & results** - 19 crypto tests, API tests; tamper, wrong key, forged timestamp all detected.

**11. Limitations & future scope** - no certificate authority; server-side signing; future: client-side signing, certificates, timestamping.

## Likely viva questions

1. **What is a digital signature?** A value computed from a document and a private key that proves the document is unchanged and was signed by the key holder.
2. **How is it different from a handwritten or electronic signature?** It is cryptographically bound to the exact content; copying it onto another document fails verification. Electronic signatures are any electronic mark of intent.
3. **What is hashing and why SHA-256?** A one-way function giving a fixed-size digest; tiny input changes alter the digest completely. SHA-256 is currently secure; MD5 and SHA-1 are broken.
4. **Why not just encrypt the document?** Encryption hides content; a signature proves origin and integrity. They solve different problems.
5. **What is public-key cryptography?** Two mathematically linked keys: private for signing, public for verifying. The private key cannot be derived from the public key.
6. **Why RSA-PSS instead of plain RSA padding?** PSS is randomised and has a security proof; it is the recommended modern padding for RSA signatures.
7. **What does each verification check mean?** Integrity: file unchanged. Key match: right public key. Authenticity: signature mathematically valid.
8. **What if someone changes one letter?** The hash changes, check 1 fails, result is INVALID.
9. **What if the private key is stolen?** The attacker can sign as the owner. That is why keys are passphrase-protected and why real systems support revocation.
10. **Why do you need certificates in real life?** A signature proves a key signed, not who owns the key. A certificate authority links a public key to a real identity.
11. **Does the server store private keys or documents?** No. Only hashes, names and public keys are stored.
12. **Why sign on the server in your demo, and what is better?** Simplicity. Better is signing in the browser or device so the private key never leaves it.
13. **What is non-repudiation?** The signer cannot easily deny signing, because only their private key could have produced the signature.
14. **Real-world uses?** Software updates, HTTPS certificates, signed PDFs, code signing, e-governance documents.
