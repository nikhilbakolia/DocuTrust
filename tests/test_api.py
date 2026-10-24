"""API tests using FastAPI's TestClient and an isolated in-memory database."""
import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import main
import models
from database import Base, get_db

DOC = b"Agreement: price is Rs. 500."


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_get_db
    main.rate_limiter.reset()
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def make_key(client, name="Alice Demo", passphrase=None):
    r = client.post("/api/keys/generate", json={"owner_name": name, "passphrase": passphrase})
    assert r.status_code == 200, r.text
    return r.json()


def sign(client, key, data=DOC, name="agreement.txt", passphrase=None):
    return client.post("/api/sign", json={
        "file_name": name, "file_b64": b64(data),
        "private_key_pem": key["private_key_pem"], "passphrase": passphrase,
    })


# ---------------------------------------------------------------- basics ---

def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_homepage_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "SignVerify" in r.text


# ------------------------------------------------------------------ keys ---

def test_generate_and_list_keys(client):
    key = make_key(client)
    assert "BEGIN PUBLIC KEY" in key["public_key_pem"]
    assert "PRIVATE KEY" in key["private_key_pem"]
    keys = client.get("/api/keys").json()
    assert len(keys) == 1 and keys[0]["owner_name"] == "Alice Demo"
    assert "private_key_pem" not in keys[0]          # private key is never stored/returned again
    assert client.get(f"/api/keys/{key['key_id']}").status_code == 200


def test_get_unknown_key_404(client):
    assert client.get("/api/keys/9999").status_code == 404


@pytest.mark.parametrize("payload", [
    {"owner_name": ""},
    {"owner_name": "   "},
    {"owner_name": "<script>alert(1)</script>"},
    {"owner_name": "x" * 61},
    {"owner_name": "Alice", "passphrase": "short"},
    {},
])
def test_generate_key_rejects_bad_input(client, payload):
    assert client.post("/api/keys/generate", json=payload).status_code == 422


# ----------------------------------------------------------- sign/verify ---

def test_sign_then_verify_valid(client):
    key = make_key(client)
    signed = sign(client, key)
    assert signed.status_code == 200
    body = signed.json()
    assert body["registered"] is True and body["signer_name"] == "Alice Demo"

    r = client.post("/api/verify", json={
        "file_name": "agreement.txt", "file_b64": b64(DOC),
        "signature_package": body["package"], "key_id": key["key_id"],
    })
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "VALID"
    assert out["signer_name"] == "Alice Demo"
    assert all(c["passed"] for c in out["checks"])


def test_verify_with_pasted_public_key(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    r = client.post("/api/verify", json={
        "file_b64": b64(DOC), "signature_package": pkg, "public_key_pem": key["public_key_pem"]})
    assert r.json()["status"] == "VALID"


def test_tampered_document_is_invalid(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    r = client.post("/api/verify", json={
        "file_b64": b64(b"Agreement: price is Rs. 5000."), "signature_package": pkg, "key_id": key["key_id"]})
    out = r.json()
    assert out["status"] == "INVALID"
    assert out["checks"][0]["passed"] is False


def test_wrong_key_is_invalid(client):
    alice = make_key(client, "Alice Demo")
    bob = make_key(client, "Bob Demo")
    pkg = sign(client, alice).json()["package"]
    r = client.post("/api/verify", json={
        "file_b64": b64(DOC), "signature_package": pkg, "key_id": bob["key_id"]})
    assert r.json()["status"] == "INVALID"


def test_encrypted_key_signing(client):
    key = make_key(client, "Carol Demo", passphrase="a-long-passphrase")
    assert key["encrypted"] is True
    assert sign(client, key).status_code == 400                        # missing passphrase
    assert sign(client, key, passphrase="wrong-passphrase").status_code == 400
    assert sign(client, key, passphrase="a-long-passphrase").status_code == 200


def test_sign_with_unregistered_key(client):
    from services import crypto_service as c
    stranger = c.generate_keypair()
    r = sign(client, stranger)
    assert r.status_code == 200 and r.json()["registered"] is False


# ------------------------------------------------------- input validation ---

def test_sign_rejects_bad_base64(client):
    key = make_key(client)
    r = client.post("/api/sign", json={"file_name": "a.txt", "file_b64": "***", "private_key_pem": key["private_key_pem"]})
    assert r.status_code == 400


def test_sign_rejects_empty_file(client):
    key = make_key(client)
    r = client.post("/api/sign", json={"file_name": "a.txt", "file_b64": "", "private_key_pem": key["private_key_pem"]})
    assert r.status_code == 422


def test_sign_rejects_garbage_private_key(client):
    r = client.post("/api/sign", json={"file_name": "a.txt", "file_b64": b64(DOC), "private_key_pem": "garbage"})
    assert r.status_code == 400


def test_sign_rejects_extremely_long_input(client):
    r = client.post("/api/sign", json={"file_name": "a.txt", "file_b64": "A" * 8_000_000, "private_key_pem": "x"})
    assert r.status_code == 422


def test_verify_requires_a_key(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    r = client.post("/api/verify", json={"file_b64": b64(DOC), "signature_package": pkg})
    assert r.status_code == 422


def test_verify_rejects_malformed_package(client):
    r = client.post("/api/verify", json={
        "file_b64": b64(DOC), "key_id": 1, "signature_package": {"version": 1, "signature_b64": "x"}})
    assert r.status_code == 422


def test_verify_unknown_key_id_404(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    r = client.post("/api/verify", json={"file_b64": b64(DOC), "signature_package": pkg, "key_id": 9999})
    assert r.status_code == 404


def test_verify_garbage_public_key(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    r = client.post("/api/verify", json={"file_b64": b64(DOC), "signature_package": pkg, "public_key_pem": "garbage"})
    assert r.status_code == 400


def test_hash_endpoint(client):
    r = client.post("/api/hash", json={"file_name": "abc.txt", "file_b64": b64(b"abc")})
    assert r.status_code == 200
    assert r.json()["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert r.json()["size_bytes"] == 3


# ------------------------------------------------------- history & stats ---

def test_history_and_stats(client):
    key = make_key(client)
    pkg = sign(client, key).json()["package"]
    client.post("/api/verify", json={"file_b64": b64(DOC), "signature_package": pkg, "key_id": key["key_id"]})
    client.post("/api/verify", json={"file_b64": b64(b"changed"), "signature_package": pkg, "key_id": key["key_id"]})

    items = client.get("/api/history").json()
    assert [i["action"] for i in items] == ["VERIFY", "VERIFY", "SIGN", "KEYGEN"]
    assert client.get(f"/api/history/{items[0]['id']}").status_code == 200
    assert client.get("/api/history/9999").status_code == 404

    s = client.get("/api/stats").json()
    assert s["registered_keys"] == 1 and s["documents_signed"] == 1
    assert s["verifications"] == 2 and s["valid_results"] == 1 and s["invalid_results"] == 1
    assert len(s["recent"]) == 4


def test_history_never_stores_documents_or_private_keys(client):
    key = make_key(client)
    sign(client, key)
    dump = str(client.get("/api/history").json()) + str(client.get("/api/keys").json())
    assert "PRIVATE KEY" not in dump
    assert b64(DOC) not in dump


def test_rate_limit(client):
    main.rate_limiter.limit = 3
    try:
        codes = [client.post("/api/hash", json={"file_name": "a", "file_b64": b64(b"a")}).status_code for _ in range(5)]
    finally:
        main.rate_limiter.limit = 120
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]
