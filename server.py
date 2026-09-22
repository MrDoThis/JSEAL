import os
import json
import uuid
import hashlib
import tempfile
import requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nacl.signing
import nacl.encoding

app = FastAPI(title="JSeal Certificate Service - Permanent Arweave")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- DB ----------
DB_PATH = os.getenv("JSEAL_DB_PATH", "certificates_db.json")

def _load_db() -> Dict[str, Any]:
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def _save_db():
    try:
        with open(DB_PATH, "w") as f:
            json.dump(certificates_db, f, indent=2)
    except Exception as e:
        print(f"[DB] save failed: {e}")

certificates_db: Dict[str, Any] = _load_db()

# ---------- SIGNING KEY ----------
SIGNING_KEY_PATH = os.getenv("JSEAL_SIGNING_KEY_PATH", "signing_key.hex")
_signing_key: Optional[nacl.signing.SigningKey] = None

def _load_or_create_signing_key():
    global _signing_key
    env_seed = os.getenv("JSEAL_SIGNING_KEY")
    if env_seed:
        try:
            _signing_key = nacl.signing.SigningKey(bytes.fromhex(env_seed.strip()))
            print("[JSeal] Signing key loaded from env JSEAL_SIGNING_KEY")
            return
        except Exception as e:
            print(f"[JSeal] Invalid JSEAL_SIGNING_KEY env: {e}")
    
    if os.path.exists(SIGNING_KEY_PATH):
        try:
            with open(SIGNING_KEY_PATH, "r") as f:
                _signing_key = nacl.signing.SigningKey(bytes.fromhex(f.read().strip()))
            print(f"[JSeal] Signing key loaded from {SIGNING_KEY_PATH}")
            return
        except Exception as e:
            print(f"[JSeal] Failed to load key file: {e}")

    _signing_key = nacl.signing.SigningKey.generate()
    try:
        with open(SIGNING_KEY_PATH, "w") as f:
            f.write(_signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
        print(f"[JSeal] NEW signing key generated -> {SIGNING_KEY_PATH}")
    except Exception:
        pass
    print(f"[JSeal] NEW Public key: {_signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()}")

_load_or_create_signing_key()

def get_public_key_hex() -> str:
    return _signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

def canonicalize(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))

def sign_payload(payload: dict):
    msg = canonicalize(payload).encode("utf-8")
    data_hash = hashlib.sha256(msg).hexdigest()
    sig = _signing_key.sign(msg).signature.hex()
    return data_hash, sig

# ---------- PERMANENT PAY-ONCE: ARWEAVE (FREE FOR <100KB) ----------
# No config needed in arweave.app - this just works.
# Your certs are 0.54KB, so ArDrive Turbo free tier covers it forever.

def upload_to_arweave_permanent(bundle: dict, cert_id: str) -> Optional[str]:
    """
    Uploads to Arweave permanently. 
    For files <100KB it's FREE via Turbo, no AR needed.
    Returns Arweave TX ID, permanent URL = https://arweave.net/{tx_id}
    """
    try:
        data = json.dumps(bundle).encode("utf-8")
        
        # 1st try: Turbo free endpoint (recommended for tiny files)
        try:
            r = requests.post(
                "https://turbo.ardrive.io/v1/data",
                data=data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            if r.status_code in (200, 201, 202):
                j = r.json() if r.text else {}
                tx_id = j.get("id") or j.get("dataTxId") or j.get("arweaveId")
                if tx_id:
                    print(f"[Arweave] SUCCESS {cert_id} -> https://arweave.net/{tx_id}")
                    return tx_id
                # Some gateways return tx id as plain text
                if r.text and len(r.text.strip()) == 43: # Arweave tx id length
                    print(f"[Arweave] SUCCESS {cert_id} -> https://arweave.net/{r.text.strip()}")
                    return r.text.strip()
            print(f"[Arweave] Turbo response {r.status_code}: {r.text[:300]}")
        except Exception as e:
            print(f"[Arweave] Turbo try failed: {e}")

        # 2nd try: Public arweave.net uploader
        try:
            r2 = requests.post(
                "https://upload.ardrive.io/v1/tx",
                data=data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            if r2.status_code in (200, 201, 202):
                j = r2.json()
                tx_id = j.get("id")
                if tx_id:
                    print(f"[Arweave] SUCCESS (fallback) {cert_id} -> https://arweave.net/{tx_id}")
                    return tx_id
        except Exception as e:
            print(f"[Arweave] Fallback try failed: {e}")

        print(f"[Arweave] All upload attempts failed for {cert_id}, will save locally only")
        return None

    except Exception as e:
        print(f"[Arweave] FAILED {cert_id}: {e}")
        import traceback
        traceback.print_exc()
        return None

def build_bundle(cert_id: str, payload: dict, data_hash: str, signature_hex: str) -> dict:
    return {
        "jseal_version": "1.0",
        "certificate_id": cert_id,
        "payload": payload,
        "hash": {"algorithm": "SHA-256", "digest_hex": data_hash},
        "signature": {"algorithm": "Ed25519", "signature_hex": signature_hex},
        "storage": {"type": "arweave", "permanent": True}
    }

def _issue_or_sign(cert_id: str, event_id: str, recipient_name: str):
    issued_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "cert_id": cert_id,
        "event_id": event_id,
        "issued_at": issued_at,
        "recipient_name": recipient_name
    }
    data_hash, signature_hex = sign_payload(payload)
    bundle = build_bundle(cert_id, payload, data_hash, signature_hex)
    
    arweave_tx_id = upload_to_arweave_permanent(bundle, cert_id)
    
    certificates_db[cert_id] = {
        "cert_id": cert_id,
        "event_id": event_id,
        "recipient_name": recipient_name,
        "issued_at": issued_at,
        "status": "ACTIVE",
        "data_hash": data_hash,
        "signature": signature_hex,
        "arweave_tx_id": arweave_tx_id,
        "permanent_url": f"https://arweave.net/{arweave_tx_id}" if arweave_tx_id else None,
        "bundle": bundle
    }
    _save_db()
    return payload, data_hash, signature_hex, arweave_tx_id

# ---------- MODELS ----------
class IssueRequest(BaseModel):
    cert_id: str
    event_id: str
    recipient_name: str
    force: bool = False

class BatchRecord(BaseModel):
    recipient_name: str
    cert_id: Optional[str] = None

class BatchIssueRequest(BaseModel):
    event_id: str
    cert_prefix: str = "cert"
    records: List[BatchRecord]
    force: bool = False

class PreprintRequest(BaseModel):
    event_id: str
    cert_prefix: str = "cert"
    quantity: int = 1

class AssignRequest(BaseModel):
    recipient_name: str

class AssignBatchRecord(BaseModel):
    cert_id: str
    recipient_name: str

class AssignBatchRequest(BaseModel):
    records: List[AssignBatchRecord]
    force: bool = False

def now_iso(): return datetime.now(timezone.utc).isoformat()

# ---------- ROUTES ----------
@app.get("/")
def root():
    return {
        "status": "JSeal Arweave live",
        "public_key_hex": get_public_key_hex(),
        "storage": "Arweave pay-once permanent (free <100KB)",
        "total_certs": len(certificates_db)
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "public_key": get_public_key_hex(),
        "total_certificates": len(certificates_db),
        "permanent_storage": "Arweave pay-once",
        "permanent_url_example": "https://arweave.net/TX_ID"
    }

@app.get("/api/v1/trust-root")
def trust_root():
    return {
        "issuer": "JSEAL",
        "algorithm": "Ed25519",
        "public_key_hex": get_public_key_hex()
    }

@app.post("/api/v1/certificates/issue")
def issue_certificate(req: IssueRequest):
    existing = certificates_db.get(req.cert_id)
    if existing and existing.get("status") != "PENDING" and not req.force:
        raise HTTPException(status_code=409, detail=f"Certificate {req.cert_id} already exists. Use force=true to reissue.")
    
    payload, data_hash, signature_hex, ar_id = _issue_or_sign(req.cert_id, req.event_id, req.recipient_name)
    return {
        "cert_id": req.cert_id,
        "payload": payload,
        "data_hash": data_hash,
        "signature": signature_hex,
        "arweave_tx_id": ar_id,
        "permanent_url": f"https://arweave.net/{ar_id}" if ar_id else None,
        "verify_url": f"https://arweave.net/{ar_id}" if ar_id else f"/api/v1/certificates/verify/{req.cert_id}"
    }

@app.get("/api/v1/certificates/verify/{cert_id}")
def verify_certificate(cert_id: str):
    record = certificates_db.get(cert_id)
    if not record:
        return {"found": False, "cert_id": cert_id}
    return {"found": True, **record}

@app.get("/api/v1/certificates")
def list_certificates():
    return {"total": len(certificates_db), "certificates": list(certificates_db.values())}

@app.post("/api/v1/certificates/batch-issue")
def batch_issue(req: BatchIssueRequest):
    issued = []
    failed = []
    for rec in req.records:
        cert_id = rec.cert_id or f"{req.cert_prefix}-{uuid.uuid4().hex[:8]}"
        if certificates_db.get(cert_id) and not req.force:
            failed.append({"cert_id": cert_id, "reason": "exists"})
            continue
        try:
            payload, dh, sig, ar_id = _issue_or_sign(cert_id, req.event_id, rec.recipient_name)
            issued.append({
                "cert_id": cert_id,
                "payload": payload,
                "data_hash": dh,
                "signature": sig,
                "arweave_tx_id": ar_id,
                "permanent_url": f"https://arweave.net/{ar_id}" if ar_id else None
            })
        except Exception as e:
            failed.append({"cert_id": cert_id, "reason": str(e)})
    return {"total_requested": len(req.records), "total_issued": len(issued), "certificates": issued, "failed": failed}

@app.post("/api/v1/certificates/preprint")
def preprint_certs(req: PreprintRequest):
    created = []
    for _ in range(req.quantity):
        cert_id = f"{req.cert_prefix}-{uuid.uuid4().hex[:8]}"
        issued_at = now_iso()
        certificates_db[cert_id] = {
            "cert_id": cert_id,
            "event_id": req.event_id,
            "recipient_name": "",
            "issued_at": issued_at,
            "status": "PENDING",
            "data_hash": None,
            "signature": None,
            "arweave_tx_id": None,
            "bundle": None
        }
        created.append({"cert_id": cert_id, "status": "PENDING"})
    _save_db()
    return {"total_created": len(created), "certificates": created}

@app.post("/api/v1/certificates/{cert_id}/assign")
def assign_certificate(cert_id: str, req: AssignRequest):
    rec = certificates_db.get(cert_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Not found")
    if rec.get("status") == "ACTIVE" and rec.get("recipient_name"):
        raise HTTPException(status_code=409, detail="Already assigned")
    payload, dh, sig, ar_id = _issue_or_sign(cert_id, rec["event_id"], req.recipient_name)
    return {
        "cert_id": cert_id,
        "payload": payload,
        "data_hash": dh,
        "signature": sig,
        "arweave_tx_id": ar_id,
        "permanent_url": f"https://arweave.net/{ar_id}" if ar_id else None
    }

@app.post("/api/v1/certificates/assign-batch")
def assign_batch(req: AssignBatchRequest):
    assigned = []
    failed = []
    for r in req.records:
        rec = certificates_db.get(r.cert_id)
        if not rec:
            failed.append({"cert_id": r.cert_id, "reason": "not found"})
            continue
        if rec.get("status") == "ACTIVE" and rec.get("recipient_name") and not req.force:
            failed.append({"cert_id": r.cert_id, "reason": "already assigned"})
            continue
        try:
            payload, dh, sig, ar_id = _issue_or_sign(r.cert_id, rec["event_id"], r.recipient_name)
            assigned.append({
                "cert_id": r.cert_id,
                "payload": payload,
                "data_hash": dh,
                "signature": sig,
                "arweave_tx_id": ar_id,
                "permanent_url": f"https://arweave.net/{ar_id}" if ar_id else None
            })
        except Exception as e:
            failed.append({"cert_id": r.cert_id, "reason": str(e)})
    return {"total_assigned": len(assigned), "assigned": assigned, "failed": failed}
