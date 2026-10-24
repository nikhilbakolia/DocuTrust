# PROJECT REPORT

## Digital Signature & Document Verification System

**Course:** Introduction to Cyber Security
**Submitted by:** Nikhil Bakolia (PRN 25030422079) and Aanya Arney (PRN 25030422003)
**Submitted to:** Veena Madaan
**Institution:** [College Name]  **Academic Year:** [Year]

---

## Abstract
Digital documents can be copied and edited without leaving visible traces, so receivers need a way to confirm that a document is genuine and unchanged. This project implements a web-based digital signature system using RSA-2048, RSASSA-PSS and SHA-256. Users generate key pairs, sign documents and verify signed documents. Verification is split into three explained checks so users learn why a result is valid or invalid. Private keys and documents are never stored.

## Chapter 1 - Introduction
A digital signature is the cryptographic equivalent of a handwritten signature, but stronger: it is mathematically bound to the exact content of the document and to the signer's private key. It is used in software updates, HTTPS certificates, contracts and government e-documents. This project demonstrates the idea end to end in a simple, explainable web application.

## Chapter 2 - Problem Statement
When a file is sent over email or the internet, the receiver cannot be sure that (a) it was not modified on the way and (b) it truly came from the claimed sender. Simple checksums detect accidental damage but not deliberate tampering, because an attacker can recompute them. A mechanism that provides integrity and authenticity is required.

## Chapter 3 - Objectives
1. Generate RSA key pairs and register public keys.
2. Sign documents using a private key.
3. Verify documents using a signature file and a public key.
4. Detect tampering, wrong keys and forged signatures, and explain each result.
5. Avoid storing private keys or documents.
6. Teach the concepts through a Learn page and a guided demo.

## Chapter 4 - Existing System
Common solutions are PDF signing tools, e-signature services, and command-line tools such as OpenSSL or GPG. Commercial services are convenient but hide how they work. Command-line tools are powerful but difficult for beginners. Neither is designed for explaining each verification step to a student.

## Chapter 5 - Proposed System
A browser-based tool backed by a Python API. It uses standard algorithms from the `cryptography` library, shows three separate verification checks, keeps an audit history, and includes a learning section with sample documents for a tamper demonstration.

## Chapter 6 - System Architecture
- **Frontend:** seven HTML pages with CSS and vanilla JavaScript, served by FastAPI.
- **Backend:** FastAPI routes, Pydantic validation, and one cryptography module (`crypto_service.py`).
- **Database:** SQLite with two tables (`public_keys`, `activity_log`).

Flow: browser → JSON request → validation → crypto service → database log → JSON response → browser display.

## Chapter 7 - Methodology
1. Define a signature package format (hash, time, key fingerprint, signature).
2. Implement the crypto service and test it in isolation.
3. Wrap it in a validated REST API.
4. Build the user interface.
5. Write automated tests, including attack scenarios (tampering, wrong key, forged time).

## Chapter 8 - Cryptographic Design
- **Hash:** SHA-256 produces a 256-bit digest of the document.
- **Key pair:** RSA with 2048-bit modulus and exponent 65537.
- **Signature scheme:** RSASSA-PSS with MGF1(SHA-256) and a 32-byte salt. PSS is randomised, so two signatures of the same data differ but both verify.
- **Signed message:** canonical JSON of `{file_sha256, signed_at, signer_fingerprint}`, so the timestamp and key identity are also protected.
- **Fingerprint:** SHA-256 of the DER-encoded public key.
- **Private key storage format:** PKCS#8 PEM, optionally encrypted with a user passphrase.

## Chapter 9 - Signing Process
The document is decoded, size-checked (max 5 MB) and hashed. The message is built and signed with the private key. The signature package is returned for download. The server logs only the file name, hash and key fingerprint.

## Chapter 10 - Verification Process
Three independent checks run:
1. **Document integrity:** recomputed hash equals the signed hash.
2. **Signer key match:** supplied public key fingerprint equals the package fingerprint.
3. **Signature authenticity:** cryptographic verification succeeds.

Result is VALID only if all three pass. The combination of failures selects an explanation: a modified document (check 1 fails, others pass), a wrong key (check 2 fails), or a forged or damaged signature (check 3 fails).

## Chapter 11 - Database Design
| Table | Columns |
|---|---|
| public_keys | id, owner_name, fingerprint (unique), public_key_pem, created_at |
| activity_log | id, action (KEYGEN/SIGN/VERIFY), file_name, file_sha256, signer_fingerprint, result, detail, created_at |

## Chapter 12 - Security Considerations
- Standard, reviewed cryptography; no custom algorithms.
- Private keys and documents are never persisted or logged.
- Pydantic validation with length limits, name pattern checks and base64 validation.
- ORM-only database access to prevent SQL injection; HTML escaping in the browser to prevent XSS.
- Generic server errors and basic rate limiting.
- Honest labelling as an educational tool.

## Chapter 13 - Testing
Automated tests cover: known SHA-256 value; one-character change alters the hash; key generation; encrypted private keys (missing and wrong passphrase); valid signature; tampered document; wrong public key; forged timestamp; forged hash; corrupted and non-base64 signatures; file decoding limits. API tests cover key generation and validation, sign and verify flows, error codes (400, 404, 422, 429), history, statistics, and that private keys and documents never appear in stored data.

## Chapter 14 - Results
The crypto test suite (19 tests) passed during development. In direct runs: an unmodified document verified as VALID; a document with one changed figure verified as INVALID with only the integrity check failing; verification with a different key failed the key-match and authenticity checks; a forged signing time failed signature authenticity.

## Chapter 15 - Limitations and Future Scope
**Limitations:** no certificate authority, so identity is not proven; signing is server-side for simplicity; in-memory rate limiting; not a legally recognised e-signature service.
**Future scope:** client-side signing with Web Crypto, certificates and revocation, trusted timestamping, ECDSA/Ed25519, PDF visible signatures, user accounts.

## Chapter 16 - Conclusion
The project shows how hashing and public-key cryptography combine to give integrity and authenticity. By explaining each check and demonstrating tampering, it works both as a functioning tool and as a teaching aid.

## References
1. NIST FIPS 186-5, Digital Signature Standard.
2. RFC 8017, PKCS #1: RSA Cryptography Specifications (RSASSA-PSS).
3. NIST FIPS 180-4, Secure Hash Standard (SHA-256).
4. Python `cryptography` library documentation.
5. FastAPI and SQLAlchemy documentation.
