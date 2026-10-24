"""Tests for the cryptographic core. Run from the project root:  pytest tests/ -v"""
import base64

import pytest

from services import crypto_service as c

DOC = b"Agreement: price is Rs. 500."


@pytest.fixture(scope="module")
def alice():
    return c.generate_keypair()


@pytest.fixture(scope="module")
def bob():
    return c.generate_keypair()


@pytest.fixture(scope="module")
def signed(alice):
    return c.sign_document(DOC, alice["private_key_pem"], None, "agreement.txt")


# ---------------------------------------------------------------- hashing ---

def test_sha256_known_value():
    # Well-known SHA-256 of the string "abc"
    assert c.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_one_character_change_changes_hash():
    assert c.sha256_hex(b"Rs. 500") != c.sha256_hex(b"Rs. 5000")


# ------------------------------------------------------------------- keys ---

def test_keypair_has_expected_parts(alice):
    assert "BEGIN PUBLIC KEY" in alice["public_key_pem"]
    assert "PRIVATE KEY" in alice["private_key_pem"]
    assert len(alice["fingerprint"]) == 64
    assert alice["encrypted"] is False


def test_two_keypairs_differ(alice, bob):
    assert alice["fingerprint"] != bob["fingerprint"]


def test_encrypted_private_key_needs_passphrase():
    kp = c.generate_keypair("a-strong-passphrase")
    assert "ENCRYPTED PRIVATE KEY" in kp["private_key_pem"]
    with pytest.raises(c.CryptoError):
        c.sign_document(DOC, kp["private_key_pem"], None, "x.txt")
    with pytest.raises(c.CryptoError):
        c.sign_document(DOC, kp["private_key_pem"], "wrong-passphrase", "x.txt")
    pkg = c.sign_document(DOC, kp["private_key_pem"], "a-strong-passphrase", "x.txt")
    assert c.verify_document(DOC, pkg, kp["public_key_pem"])["status"] == "VALID"


def test_unneeded_passphrase_rejected(alice):
    with pytest.raises(c.CryptoError):
        c.sign_document(DOC, alice["private_key_pem"], "not-needed", "x.txt")


def test_garbage_keys_rejected():
    with pytest.raises(c.CryptoError):
        c.load_private_key("not a key")
    with pytest.raises(c.CryptoError):
        c.load_public_key("not a key")


# --------------------------------------------------------- sign + verify ---

def test_valid_signature(alice, signed):
    result = c.verify_document(DOC, signed, alice["public_key_pem"])
    assert result["status"] == "VALID"
    assert all(chk["passed"] for chk in result["checks"])
    assert signed["signer_fingerprint"] == alice["fingerprint"]


def test_tampered_document_detected(alice, signed):
    result = c.verify_document(b"Agreement: price is Rs. 5000.", signed, alice["public_key_pem"])
    assert result["status"] == "INVALID"
    integrity, key_match, authenticity = result["checks"]
    assert integrity["passed"] is False
    assert key_match["passed"] is True and authenticity["passed"] is True  # signature itself is genuine
    assert "modified" in result["summary"]


def test_wrong_public_key_detected(bob, signed):
    result = c.verify_document(DOC, signed, bob["public_key_pem"])
    assert result["status"] == "INVALID"
    assert result["checks"][1]["passed"] is False


def test_forged_timestamp_detected(alice, signed):
    forged = dict(signed, signed_at="2000-01-01T00:00:00Z")
    result = c.verify_document(DOC, forged, alice["public_key_pem"])
    assert result["status"] == "INVALID"
    assert result["checks"][2]["passed"] is False


def test_forged_hash_in_package_detected(alice, signed):
    forged = dict(signed, file_sha256=c.sha256_hex(b"something else"))
    assert c.verify_document(DOC, forged, alice["public_key_pem"])["status"] == "INVALID"


def test_corrupted_signature_detected(alice, signed):
    forged = dict(signed, signature_b64=base64.b64encode(b"\x00" * 256).decode())
    result = c.verify_document(DOC, forged, alice["public_key_pem"])
    assert result["status"] == "INVALID"
    assert result["checks"][2]["passed"] is False


def test_non_base64_signature_does_not_crash(alice, signed):
    forged = dict(signed, signature_b64="!!!not-base64!!!")
    assert c.verify_document(DOC, forged, alice["public_key_pem"])["status"] == "INVALID"


def test_signatures_are_randomised_but_both_valid(alice):
    p1 = c.sign_document(DOC, alice["private_key_pem"], None, "a.txt")
    p2 = c.sign_document(DOC, alice["private_key_pem"], None, "a.txt")
    # PSS uses a random salt, so two signatures over the same bytes normally differ
    assert p1["signature_b64"] != p2["signature_b64"]
    assert c.verify_document(DOC, p1, alice["public_key_pem"])["status"] == "VALID"
    assert c.verify_document(DOC, p2, alice["public_key_pem"])["status"] == "VALID"


# ------------------------------------------------------------ file input ---

def test_decode_file_ok():
    assert c.decode_file(base64.b64encode(b"hello").decode()) == b"hello"


def test_decode_file_rejects_bad_base64():
    with pytest.raises(c.CryptoError):
        c.decode_file("***not base64***")


def test_decode_file_rejects_empty():
    with pytest.raises(c.CryptoError):
        c.decode_file("")


def test_decode_file_rejects_oversized():
    big = base64.b64encode(b"a" * (c.MAX_FILE_BYTES + 1)).decode()
    with pytest.raises(c.CryptoError):
        c.decode_file(big)
