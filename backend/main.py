"""
main.py
-------
FastAPI application: JSON API under /api/... and the web pages served from ../frontend.
Run from the backend/ folder:   uvicorn main:app --reload --port 8000
Then open:                      http://127.0.0.1:8000

SECURITY NOTES
 * Private keys and documents are processed in memory only; they are never saved or logged.
 * All input is validated by Pydantic (types, lengths, formats).
 * All database access uses the SQLAlchemy ORM (parameterised queries -> no SQL injection).
 * Users never see stack traces; unexpected errors return a generic message.
 * Simple in-memory rate limiting protects the heavier endpoints.
"""

import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db, init_db
from services import crypto_service as crypto

logger = logging.getLogger("signature_app")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Digital Signature & Document Verification System",
    description="Educational project: RSA-PSS digital signatures with SHA-256.",
    version="1.0.0",
    lifespan=lifespan,
)


# ------------------------------------------------------- rate limiting ---

class RateLimiter:
    """Allow at most `limit` requests per `window` seconds per client IP (in memory)."""

    def __init__(self, limit: int = 120, window: int = 60):
        self.limit = limit
        self.window = window
        self.hits = defaultdict(deque)

    def reset(self):
        self.hits.clear()

    def __call__(self, request: Request):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        q = self.hits[ip]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(status_code=429, detail="Too many requests. Please wait a minute and try again.")
        q.append(now)


rate_limiter = RateLimiter()


# ------------------------------------------------------ error handling ---

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    """Return ONE short, readable message instead of Pydantic's long error list."""
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", []) if p != "body")
    msg = str(first.get("msg", "Invalid input")).replace("Value error, ", "")
    text = f"{field}: {msg}" if field else msg
    return JSONResponse(status_code=422, content={"detail": text})


@app.exception_handler(crypto.CryptoError)
async def crypto_error_handler(request: Request, exc: crypto.CryptoError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.exception("Unexpected error")  # details go to the server log only
    return JSONResponse(status_code=500, content={"detail": "Something went wrong on the server. Please try again."})


# --------------------------------------------------------------- helpers ---

def log_activity(db: Session, action: str, result: str, detail: str,
                 file_name=None, file_sha256=None, fingerprint=None):
    db.add(models.ActivityLog(
        action=action, result=result, detail=detail[:500],
        file_name=(file_name or None) and file_name[:255],
        file_sha256=file_sha256, signer_fingerprint=fingerprint,
    ))
    db.commit()


def find_key_by_fingerprint(db: Session, fingerprint: str):
    return db.query(models.PublicKey).filter(models.PublicKey.fingerprint == fingerprint.lower()).first()


# ------------------------------------------------------------ endpoints ---

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "digital-signature-system", "algorithm": crypto.ALGORITHM}


@app.post("/api/keys/generate", response_model=schemas.KeyGenResponse, dependencies=[Depends(rate_limiter)])
def generate_key(req: schemas.KeyGenRequest, db: Session = Depends(get_db)):
    pair = crypto.generate_keypair(req.passphrase)
    key = models.PublicKey(
        owner_name=req.owner_name,
        fingerprint=pair["fingerprint"],
        public_key_pem=pair["public_key_pem"],
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    log_activity(db, "KEYGEN", "OK", f"Key pair generated for {req.owner_name}", fingerprint=key.fingerprint)
    return schemas.KeyGenResponse(
        key_id=key.id,
        owner_name=key.owner_name,
        fingerprint=key.fingerprint,
        short_fingerprint=crypto.short_fingerprint(key.fingerprint),
        public_key_pem=key.public_key_pem,
        private_key_pem=pair["private_key_pem"],
        encrypted=pair["encrypted"],
        created_at=schemas._iso(key.created_at),
    )


@app.get("/api/keys", response_model=list[schemas.PublicKeyOut])
def list_keys(db: Session = Depends(get_db)):
    return db.query(models.PublicKey).order_by(models.PublicKey.id.desc()).limit(200).all()


@app.get("/api/keys/{key_id}", response_model=schemas.PublicKeyOut)
def get_key(key_id: int, db: Session = Depends(get_db)):
    key = db.get(models.PublicKey, key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="Key not found.")
    return key


@app.post("/api/hash", response_model=schemas.HashResponse, dependencies=[Depends(rate_limiter)])
def hash_file(req: schemas.HashRequest):
    data = crypto.decode_file(req.file_b64)
    return schemas.HashResponse(
        file_name=req.file_name,
        size_bytes=len(data),
        sha256=crypto.sha256_hex(data),
        sha512=crypto.sha512_hex(data),
    )


@app.post("/api/sign", response_model=schemas.SignResponse, dependencies=[Depends(rate_limiter)])
def sign(req: schemas.SignRequest, db: Session = Depends(get_db)):
    data = crypto.decode_file(req.file_b64)
    package = crypto.sign_document(data, req.private_key_pem, req.passphrase, req.file_name)
    key = find_key_by_fingerprint(db, package["signer_fingerprint"])
    who = key.owner_name if key else "unregistered key"
    log_activity(db, "SIGN", "OK", f"Document signed by {who}",
                 file_name=req.file_name, file_sha256=package["file_sha256"],
                 fingerprint=package["signer_fingerprint"])
    return schemas.SignResponse(package=package, signer_name=key.owner_name if key else None,
                                registered=key is not None)


@app.post("/api/verify", response_model=schemas.VerifyResponse, dependencies=[Depends(rate_limiter)])
def verify(req: schemas.VerifyRequest, db: Session = Depends(get_db)):
    data = crypto.decode_file(req.file_b64)

    if req.key_id is not None and not (req.public_key_pem or "").strip():
        key = db.get(models.PublicKey, req.key_id)
        if key is None:
            raise HTTPException(status_code=404, detail="Selected signer key was not found.")
        public_pem = key.public_key_pem
    else:
        public_pem = req.public_key_pem

    package = req.signature_package.model_dump()
    result = crypto.verify_document(data, package, public_pem)

    registered = find_key_by_fingerprint(db, package["signer_fingerprint"])
    log_activity(db, "VERIFY", result["status"], result["summary"],
                 file_name=req.file_name or package["file_name"],
                 file_sha256=result["file_sha256"], fingerprint=package["signer_fingerprint"])
    return schemas.VerifyResponse(
        status=result["status"],
        summary=result["summary"],
        checks=result["checks"],
        file_sha256=result["file_sha256"],
        signer_name=registered.owner_name if registered else None,
        signed_at=package["signed_at"],
    )


@app.get("/api/history", response_model=list[schemas.ActivityOut])
def history(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    return db.query(models.ActivityLog).order_by(models.ActivityLog.id.desc()).limit(limit).all()


@app.get("/api/history/{item_id}", response_model=schemas.ActivityOut)
def history_item(item_id: int, db: Session = Depends(get_db)):
    item = db.get(models.ActivityLog, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Record not found.")
    return item


@app.get("/api/stats", response_model=schemas.StatsOut)
def stats(db: Session = Depends(get_db)):
    A = models.ActivityLog

    def count(action=None, result=None):
        q = db.query(func.count(A.id))
        if action:
            q = q.filter(A.action == action)
        if result:
            q = q.filter(A.result == result)
        return q.scalar() or 0

    recent = db.query(A).order_by(A.id.desc()).limit(5).all()
    return schemas.StatsOut(
        registered_keys=db.query(func.count(models.PublicKey.id)).scalar() or 0,
        documents_signed=count("SIGN"),
        verifications=count("VERIFY"),
        valid_results=count("VERIFY", "VALID"),
        invalid_results=count("VERIFY", "INVALID"),
        recent=recent,
    )


# Serve the web pages. This MUST be last so it never hides the /api routes.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
