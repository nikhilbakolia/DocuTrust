"""
crypto_service.py
-----------------
All cryptography for the project lives here, so it is easy to explain and test.

We never invent our own cryptography. We use the well-reviewed `cryptography`
library and standard algorithms:

  * Key pair      : RSA, 2048-bit
  * Hash          : SHA-256
  * Signature     : RSASSA-PSS (a modern, recommended RSA signature padding)

HOW SIGNING WORKS (simplified)
  1. Hash the document with SHA-256  -> a short fixed-size "fingerprint" of the file.
  2. Build a small message: {file hash, signing time, signer key fingerprint}.
  3. Sign that message with the signer's PRIVATE key.
  4. Share the document + the signature package. Keep the private key secret!

HOW VERIFYING WORKS
  1. Re-hash the received document and compare with the hash in the package
     (detects ANY change to the document -> integrity).
  2. Check the public key really is the one the signer used (fingerprint).
  3. Verify the signature using the signer's PUBLIC key
     (proves the holder of the private key signed it -> authenticity).
"""

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_SIZE = 2048
SALT_LENGTH = 32  # bytes; equals SHA-256 digest size (standard choice for PSS)
ALGORITHM = "RSA-2048 / RSASSA-PSS / SHA-256"
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB limit per document
PACKAGE_VERSION = 1


class CryptoError(ValueError):
    """Raised for any user-facing problem (bad input, wrong passphrase, ...).
    The message is safe to show to the user."""


# ---------------------------------------------------------------- helpers ---

def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LENGTH)


def decode_file(file_b64: str) -> bytes:
    """Decode base64 file content sent by the browser and enforce size limits."""
    try:
        data = base64.b64decode(file_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CryptoError("The file content is not valid base64.")
    if len(data) == 0:
        raise CryptoError("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise CryptoError(f"The file is too large (limit is {MAX_FILE_BYTES // (1024 * 1024)} MB).")
    return data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def short_fingerprint(fingerprint: str) -> str:
    """Human-friendly form, e.g. 'AB:CD:12:34:56:78:9A:BC'."""
    head = fingerprint[:16].upper()
    return ":".join(head[i:i + 2] for i in range(0, len(head), 2))


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 over the DER encoding of the public key. Identifies a key uniquely."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def build_signed_message(file_sha256: str, signed_at: str, signer_fingerprint: str) -> bytes:
    """The exact bytes that get signed. Canonical JSON so both sides rebuild it identically.
    Including the timestamp and key fingerprint means they are protected by the signature too."""
    payload = {
        "file_sha256": file_sha256,
        "signed_at": signed_at,
        "signer_fingerprint": signer_fingerprint,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ------------------------------------------------------------ key loading ---

def load_private_key(pem: str, passphrase: Optional[str] = None) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(
            pem.strip().encode("utf-8"),
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except TypeError:
        # Raised when a password is needed but not given, or given but not needed.
        if passphrase:
            raise CryptoError("This private key is not encrypted, so leave the passphrase empty.")
        raise CryptoError("This private key is encrypted. Please enter its passphrase.")
    except (ValueError, UnsupportedAlgorithm):
        raise CryptoError("Could not read the private key. Check the PEM text and the passphrase.")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("Only RSA private keys are supported.")
    return key


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.strip().encode("utf-8"))
    except (ValueError, UnsupportedAlgorithm):
        raise CryptoError("Could not read the public key. Make sure it is a valid PEM public key.")
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("Only RSA public keys are supported.")
    return key


# -------------------------------------------------------------- key pairs ---

def generate_keypair(passphrase: Optional[str] = None) -> dict:
    """Create a new RSA key pair. Returns PEM strings plus the public key fingerprint.
    If a passphrase is given, the private key PEM is encrypted with it."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    ).decode("utf-8")
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return {
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
        "fingerprint": public_key_fingerprint(public_key),
        "encrypted": bool(passphrase),
    }


# ---------------------------------------------------------------- signing ---

def sign_document(
    data: bytes,
    private_key_pem: str,
    passphrase: Optional[str],
    file_name: str,
) -> dict:
    """Sign a document and return the 'signature package' (a small JSON-able dict)."""
    private_key = load_private_key(private_key_pem, passphrase)
    fingerprint = public_key_fingerprint(private_key.public_key())
    file_hash = sha256_hex(data)
    signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    message = build_signed_message(file_hash, signed_at, fingerprint)
    signature = private_key.sign(message, _pss(), hashes.SHA256())

    return {
        "version": PACKAGE_VERSION,
        "algorithm": ALGORITHM,
        "file_name": file_name,
        "file_sha256": file_hash,
        "signed_at": signed_at,
        "signer_fingerprint": fingerprint,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


# -------------------------------------------------------------- verifying ---

def verify_document(data: bytes, package: dict, public_key_pem: str) -> dict:
    """Verify a document against a signature package and a public key.

    Returns:
        {
          "status": "VALID" | "INVALID",
          "summary": plain-English explanation,
          "checks": [ {name, passed, detail}, ... ],
          "file_sha256": hash of the document that was just checked
        }
    The result is VALID only if ALL three checks pass.
    """
    public_key = load_public_key(public_key_pem)
    actual_hash = sha256_hex(data)
    checks = []

    # Check 1 - Document integrity: is this exactly the file that was signed?
    integrity_ok = actual_hash == str(package.get("file_sha256", "")).lower()
    checks.append({
        "name": "Document integrity",
        "passed": integrity_ok,
        "detail": (
            "The document's SHA-256 hash matches the hash that was signed."
            if integrity_ok
            else "The document's hash does NOT match the signed hash. The file was changed after signing, or it is a different file."
        ),
    })

    # Check 2 - Key match: is this the key that the signer says they used?
    key_fp = public_key_fingerprint(public_key)
    key_ok = key_fp == str(package.get("signer_fingerprint", "")).lower()
    checks.append({
        "name": "Signer key match",
        "passed": key_ok,
        "detail": (
            "The public key matches the signer fingerprint in the signature package."
            if key_ok
            else "The public key does NOT match the signer fingerprint in the package. You may be using the wrong public key."
        ),
    })

    # Check 3 - Signature authenticity: was the signature really made by the matching private key?
    signature_ok = False
    sig_detail = ""
    try:
        signature = base64.b64decode(package.get("signature_b64", ""), validate=True)
        message = build_signed_message(
            str(package.get("file_sha256", "")).lower(),
            str(package.get("signed_at", "")),
            str(package.get("signer_fingerprint", "")).lower(),
        )
        public_key.verify(signature, message, _pss(), hashes.SHA256())
        signature_ok = True
        sig_detail = "The cryptographic signature is mathematically valid for this public key."
    except (InvalidSignature, binascii.Error, ValueError):
        sig_detail = ("The cryptographic signature is NOT valid for this public key. "
                      "The signature or its details were altered, or a different key signed it.")
    checks.append({"name": "Signature authenticity", "passed": signature_ok, "detail": sig_detail})

    status = "VALID" if all(c["passed"] for c in checks) else "INVALID"
    return {
        "status": status,
        "summary": _summarise(integrity_ok, key_ok, signature_ok),
        "checks": checks,
        "file_sha256": actual_hash,
    }


def _summarise(integrity_ok: bool, key_ok: bool, signature_ok: bool) -> str:
    if integrity_ok and key_ok and signature_ok:
        return ("Signature is VALID. The document has not been changed since it was signed, "
                "and the signature was created by the holder of the matching private key.")
    if signature_ok and key_ok and not integrity_ok:
        return ("Signature is INVALID: the signature itself is genuine, but the document is different "
                "from the one that was signed. It has been modified (tampered with) or replaced.")
    if not key_ok:
        return ("Signature is INVALID: the public key provided does not belong to the signer named in "
                "the signature package. Use the correct signer's public key.")
    return ("Signature is INVALID: the signature does not verify. The signature package may have been "
            "altered or damaged, or it was not created by this signer.")
