"""
models.py
---------
Database tables.

IMPORTANT (privacy by design): we store ONLY public information.
 - Private keys are NEVER stored.
 - Uploaded documents are NEVER stored (only their SHA-256 hash).
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text

from database import Base


def utcnow():
    return datetime.now(timezone.utc)


class PublicKey(Base):
    """A registered signer: owner name + public key (safe to share)."""
    __tablename__ = "public_keys"

    id = Column(Integer, primary_key=True, index=True)
    owner_name = Column(String(60), nullable=False)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 of the public key
    public_key_pem = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ActivityLog(Base):
    """Audit trail of KEYGEN / SIGN / VERIFY actions."""
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(10), nullable=False)          # KEYGEN | SIGN | VERIFY
    file_name = Column(String(255), nullable=True)
    file_sha256 = Column(String(64), nullable=True)
    signer_fingerprint = Column(String(64), nullable=True)
    result = Column(String(10), nullable=False)          # OK | VALID | INVALID
    detail = Column(String(500), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
