"""
schemas.py
----------
Pydantic models = input validation + clean JSON responses.
Every field has a length limit, so oversized or malformed input is rejected early.
"""

import re
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

NAME_PATTERN = re.compile(r"^[A-Za-z0-9 .,'_-]+$")
HEX64 = r"^[0-9a-fA-F]{64}$"
MAX_B64_LEN = 7_200_000  # ~5 MB of file data after base64 expansion


def _iso(dt: Optional[datetime]) -> Optional[str]:
    """Always send timestamps as UTC ISO strings so the browser shows local time correctly."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ------------------------------------------------------------------ keys ---

class KeyGenRequest(BaseModel):
    owner_name: str = Field(min_length=1, max_length=60)
    passphrase: Optional[str] = Field(default=None, max_length=128)

    @field_validator("owner_name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Owner name cannot be empty.")
        if not NAME_PATTERN.match(v):
            raise ValueError("Owner name may only contain letters, numbers, spaces and . , ' _ -")
        return v

    @field_validator("passphrase")
    @classmethod
    def clean_passphrase(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        if len(v) < 8:
            raise ValueError("Passphrase must be at least 8 characters (or leave it empty).")
        return v


class KeyGenResponse(BaseModel):
    key_id: int
    owner_name: str
    fingerprint: str
    short_fingerprint: str
    public_key_pem: str
    private_key_pem: str   # shown ONCE, never stored on the server
    encrypted: bool
    created_at: str


class PublicKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_name: str
    fingerprint: str
    public_key_pem: str
    created_at: Optional[datetime] = None

    @field_serializer("created_at")
    def ser_dt(self, dt):
        return _iso(dt)


# --------------------------------------------------------- sign / verify ---

class SignaturePackage(BaseModel):
    version: int = Field(ge=1, le=1)
    algorithm: str = Field(max_length=100)
    file_name: str = Field(max_length=255)
    file_sha256: str = Field(pattern=HEX64)
    signed_at: str = Field(max_length=40)
    signer_fingerprint: str = Field(pattern=HEX64)
    signature_b64: str = Field(min_length=1, max_length=2000)


class SignRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    file_b64: str = Field(min_length=1, max_length=MAX_B64_LEN)
    private_key_pem: str = Field(min_length=1, max_length=10_000)
    passphrase: Optional[str] = Field(default=None, max_length=128)

    @field_validator("passphrase")
    @classmethod
    def empty_to_none(cls, v):
        return v or None


class SignResponse(BaseModel):
    package: SignaturePackage
    signer_name: Optional[str] = None   # filled in if the key is registered
    registered: bool = False


class VerifyRequest(BaseModel):
    file_name: Optional[str] = Field(default=None, max_length=255)
    file_b64: str = Field(min_length=1, max_length=MAX_B64_LEN)
    signature_package: SignaturePackage
    key_id: Optional[int] = Field(default=None, ge=1)
    public_key_pem: Optional[str] = Field(default=None, max_length=10_000)

    @model_validator(mode="after")
    def need_a_key(self):
        if self.key_id is None and not (self.public_key_pem or "").strip():
            raise ValueError("Provide a public key: choose a registered signer or paste a PEM public key.")
        return self


class CheckResult(BaseModel):
    name: str
    passed: bool
    detail: str


class VerifyResponse(BaseModel):
    status: str                 # VALID | INVALID
    summary: str
    checks: List[CheckResult]
    file_sha256: str
    signer_name: Optional[str] = None
    signed_at: str


class HashRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    file_b64: str = Field(min_length=1, max_length=MAX_B64_LEN)


class HashResponse(BaseModel):
    file_name: str
    size_bytes: int
    sha256: str
    sha512: str


# --------------------------------------------------------- history / stats ---

class ActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    action: str
    file_name: Optional[str] = None
    file_sha256: Optional[str] = None
    signer_fingerprint: Optional[str] = None
    result: str
    detail: str
    created_at: Optional[datetime] = None

    @field_serializer("created_at")
    def ser_dt(self, dt):
        return _iso(dt)


class StatsOut(BaseModel):
    registered_keys: int
    documents_signed: int
    verifications: int
    valid_results: int
    invalid_results: int
    recent: List[ActivityOut]
