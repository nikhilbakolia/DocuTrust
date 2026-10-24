# Digital Signature & Document Verification System

An **Introduction to Cyber Security** project. A web application where users generate RSA key pairs, **digitally sign** documents, and **verify** signed documents. Any change to a document, even one character, is detected and explained.

> Educational project. It is not a legally recognised e-signature service. Use made-up demo data, never real confidential documents or real private keys.

---

## 1. Features

- **Key management:** generate RSA-2048 key pairs; optional passphrase encrypts the private key file; public keys are kept in a registry.
- **Sign a document:** any file type up to 5 MB. Produces a downloadable `.sig.json` signature package.
- **Verify a document:** three separate checks (document integrity, signer key match, signature authenticity) with a plain-English explanation.
- **Activity history:** audit trail of key generation, signing and verification (stores hashes and file names only).
- **Dashboard:** counts of keys, signed documents, valid and invalid verifications.
- **Learn page:** hashing, public-key cryptography, signing flow, threats, and a live SHA-256 demo.
- **Sample documents:** an original and a tampered copy so you can demonstrate detection.

## 2. How it works

**Signing**
1. SHA-256 hash of the document.
2. Build a small message: `{file_sha256, signed_at, signer_fingerprint}` (canonical JSON).
3. Sign the message with the **private key** using **RSASSA-PSS (SHA-256)**.
4. Output a signature package (hash, time, key fingerprint, signature).

**Verifying**
1. *Document integrity:* re-hash the received file; must equal the signed hash.
2. *Signer key match:* fingerprint of the supplied public key must equal the one in the package.
3. *Signature authenticity:* verify the signature with the public key.

All three must pass for **VALID**. Failing combinations give different explanations (modified document, wrong key, forged or damaged signature).

## 3. Technology

| Part | Choice |
|---|---|
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Cryptography | `cryptography` library (no home-made crypto) |
| Algorithms | RSA-2048, RSASSA-PSS, SHA-256 |
| Database | SQLite via SQLAlchemy |
| Frontend | HTML, CSS, vanilla JavaScript (served by FastAPI) |
| Tests | pytest |

## 4. Project structure

```
digital-signature-system/
├── backend/
│   ├── main.py                 # FastAPI app: API routes + serves the frontend
│   ├── database.py             # SQLite connection
│   ├── models.py               # Tables: public_keys, activity_log
│   ├── schemas.py              # Pydantic request/response models + validation
│   ├── services/
│   │   └── crypto_service.py   # ALL cryptography (keys, sign, verify, hash)
│   └── requirements.txt
├── frontend/
│   ├── index.html keys.html sign.html verify.html history.html learn.html about.html
│   ├── css/style.css
│   ├── js/ (main.js, index.js, keys.js, sign.js, verify.js, history.js, learn.js)
│   └── samples/ (sample_document.txt, sample_document_tampered.txt)
├── tests/
│   ├── test_crypto_service.py
│   ├── test_api.py
│   └── conftest.py
├── PROJECT_REPORT.md
├── PRESENTATION.md
├── requirements.txt
└── README.md
```

## 5. Installation (Windows 10/11)

1. **Check Python:** open Command Prompt and run `python --version`. If it fails, install Python 3.10+ from python.org and tick **"Add Python to PATH"**.
2. **Open a terminal in the project folder** (the one containing `README.md`). In File Explorer click the address bar, type `cmd`, press Enter.
3. **Create a virtual environment:** `python -m venv venv`
4. **Activate it:** `venv\Scripts\activate.bat` (you should see `(venv)`).
5. **Install packages:** `pip install -r requirements.txt`

## 6. Run

```
cd backend
uvicorn main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** in your browser. One server handles both the API and the web pages. Interactive API docs: http://127.0.0.1:8000/docs

## 7. Run the tests

From the project root (with the virtual environment active):

```
pytest tests/ -v
```

## 8. Demo flow (about 5 minutes)

1. **Keys:** create a key pair for "Student A" (set a passphrase). Download both PEM files.
2. **Sign:** upload `frontend/samples/sample_document.txt` and your private key; download `.sig.json`.
3. **Verify:** upload the same document, the `.sig.json`, choose the signer. Result: **VALID**.
4. **Tamper:** verify again using `sample_document_tampered.txt` (price changed 500 → 5000). Result: **INVALID**, "Document integrity" fails.
5. **Wrong key:** create a second key pair and verify with it. "Signer key match" fails.
6. **History / Dashboard:** show the audit trail and counts.

## 9. API summary

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Server status |
| POST | `/api/keys/generate` | Create key pair (private key returned once, never stored) |
| GET | `/api/keys`, `/api/keys/{id}` | Registered public keys |
| POST | `/api/sign` | Sign a document (base64 file + private key) |
| POST | `/api/verify` | Verify document + signature package + public key |
| POST | `/api/hash` | SHA-256 / SHA-512 of a file |
| GET | `/api/history`, `/api/history/{id}` | Activity log |
| GET | `/api/stats` | Dashboard numbers |

Example verify response:
```json
{
  "status": "INVALID",
  "summary": "Signature is INVALID: the signature itself is genuine, but the document is different ...",
  "checks": [
    {"name": "Document integrity", "passed": false, "detail": "..."},
    {"name": "Signer key match", "passed": true, "detail": "..."},
    {"name": "Signature authenticity", "passed": true, "detail": "..."}
  ]
}
```

## 10. Database

- `public_keys(id, owner_name, fingerprint UNIQUE, public_key_pem, created_at)`
- `activity_log(id, action, file_name, file_sha256, signer_fingerprint, result, detail, created_at)`

Private keys and documents are **never** stored.

## 11. Cybersecurity considerations

- Standard algorithms from a reviewed library; PSS padding; SHA-256.
- Private keys exist only in memory during signing; never saved or logged; optional passphrase encryption on download.
- Strict input validation: types, lengths, formats, 5 MB limit, base64 validation.
- ORM only, so no SQL injection. User text is escaped in the browser, so no XSS.
- Generic error messages (no stack traces); basic rate limiting.

## 12. Limitations

- No certificate authority, so a key's registered name is not proof of real-world identity.
- Signing is done server-side for demo simplicity. A real product signs on the user's device.
- Rate limiter is in memory (single process).
- Not a legally recognised e-signature service.

## 13. Future enhancements

- Client-side signing with the browser Web Crypto API.
- Certificates and a simple certificate authority.
- Trusted timestamping, ECDSA/Ed25519 support, batch signing, PDF visible signatures.
- User accounts and revocation of compromised keys.

## 14. Testing note

The crypto test-suite (19 tests) was run during development. The API tests (`tests/test_api.py`) need FastAPI installed; run `pytest tests/ -v` on your machine after installing requirements.
