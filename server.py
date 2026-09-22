import os
import json
import hashlib
import requests
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from nacl.signing import SigningKey

app = FastAPI(title="JSeal Secure Certification Engine - PERMANENT Lighthouse Edition")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REGISTRY_FILE = "jseal_registry.json"
KEY_MANIFEST_FILE = "jseal_key_manifest.json"

# ========== NEW: HOUSE PERMANENT STORAGE ==========
LIGHTHOUSE_API_URL = "https://node.lighthouse.storage/api/v0/add"

def upload_to_lighthouse(cert_data: dict, cert_id: str) -> str | None:
    """Upload to Lighthouse IPFS + Filecoin - FIXED URL"""
    api_key = os.getenv("LIGHTHOUSE_API_KEY") or os.getenv("LIGHTHOUSE_AUTH_KEY")
    if not api_key:
        print("[Lighthouse] No key")
        return None

    try:
        # Lighthouse expects file upload
        json_bytes = json.dumps(cert_data).encode('utf-8')
        files = {'file': (f'{cert_id}.json', json_bytes, 'application/json')}

        # FIXED HEADERS - Lighthouse uses Bearer token
        headers = {
            'Authorization': f'Bearer {api_key.strip()}'
        }

        resp = requests.post(LIGHTHOUSE_API_URL, files=files, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        # CID is in Hash
        cid = data.get('Hash') or data.get('cid')
        if cid:
            print(f"[Lighthouse] SUCCESS {cert_id} -> CID: {cid}")
            return cid
        print(f"[Lighthouse] No CID in response: {data}")
        return None

    except Exception as e:
        print(f"[Lighthouse] Upload failed for {cert_id}: {e}")
        return None

    try:
        # Lighthouse expects multipart file upload
        json_bytes = json.dumps(bundle, indent=2).encode('utf-8')
        files = {'file': (f'{cert_id}.json', json_bytes, 'application/json')}
        headers = {'Authorization': f'Bearer {api_key}'}

        resp = requests.post(LIGHTHOUSE_API_URL, files=files, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        cid = data.get('Hash') or data.get('cid')
        print(f"[Lighthouse] Uploaded {cert_id} -> CID: {cid}")
        return cid
    except Exception as e:
        print(f"[Lighthouse] Upload failed for {cert_id}: {e} - but certificate is still signed and saved locally")
        return None
# ========== END LIGHTHOUSE ==========

def get_delegated_key_hex():
    key_hex = os.getenv("JSEAL_DELEGATED_KEY_HEX")
    if key_hex:
        return key_hex
    if os.path.exists(KEY_MANIFEST_FILE):
        try:
            with open(KEY_MANIFEST_FILE, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            print(f"[dev-mode] Falling back to {KEY_MANIFEST_FILE}")
            return manifest["delegated_operational_key"]["private_key_hex"]
        except (json.JSONDecodeError, KeyError):
            pass
    return None

def load_registry():
    if not os.path.exists(REGISTRY_FILE):
        return {}
    try:
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_registry(registry_data):
    tmp = REGISTRY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(registry_data, f, indent=2)
    os.replace(tmp, REGISTRY_FILE)

class SigningError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code

PENDING_NAME_PLACEHOLDER = "PENDING_ASSIGNMENT"

def _next_index_for_prefix(prefix: str) -> int:
    registry = load_registry()
    max_idx = 0
    needle = prefix + "-"
    for cid in registry.keys():
        if cid.startswith(needle):
            suffix = cid[len(needle):]
            if suffix.isdigit():
                max_idx = max(max_idx, int(suffix))
    return max_idx + 1

def sign_payload(cert_id: str, event_id: str, recipient_name: str, force: bool = False,
                  status: str = "ACTIVE", archive: bool = True) -> dict:
    cert_id = (cert_id or "").strip()
    recipient_name = (recipient_name or "").strip()
    event_id = (event_id or "").strip()

    if not cert_id:
        raise SigningError("Certificate ID cannot be empty.", 400)
    if not recipient_name:
        raise SigningError("Recipient name cannot be empty.", 400)
    if not event_id:
        raise SigningError("Event ID cannot be empty.", 400)

    key_hex = get_delegated_key_hex()
    if not key_hex:
        raise SigningError(f"No signing key found. Set JSEAL_DELEGATED_KEY_HEX", 500)

    registry = load_registry()
    if cert_id in registry and not force:
        raise SigningError(f"Certificate ID '{cert_id}' already exists", 409)

    try:
        signing_key = SigningKey(bytes.fromhex(key_hex))
    except Exception as e:
        raise SigningError(f"Invalid private key format: {e}", 500)

    issued_at = datetime.utcnow().isoformat() + "Z"
    payload = {
        "cert_id": cert_id,
        "event_id": event_id,
        "issued_at": issued_at,
        "recipient_name": recipient_name,
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_bytes = canonical_payload.encode("utf-8")

    data_hash = hashlib.sha256(payload_bytes).hexdigest()
    signature_hex = signing_key.sign(payload_bytes).signature.hex()

    # PERMANENT ARCHIVAL TO LIGHTHOUSE (IPFS + Filecoin)
    lighthouse_cid = None
    gateway_url = None
    if archive:
        bundle = {
            "jseal_version": "2.0-permanent-lighthouse",
            "certificate_id": cert_id,
            "payload": payload,
            "hash": {"algorithm": "SHA-256", "digest_hex": data_hash},
            "signature": {"algorithm": "Ed25519", "signature_hex": signature_hex},
            "storage": "IPFS + Filecoin via Lighthouse - PERMANENT"
        }
        lighthouse_cid = upload_to_lighthouse(cert_id, bundle)
        if lighthouse_cid:
            gateway_url = f"https://gateway.lighthouse.storage/ipfs/{lighthouse_cid}"
            # Update bundle with its own CID for self-reference
            bundle["lighthouse_cid"] = lighthouse_cid
            bundle["gateway_url"] = gateway_url

    registry[cert_id] = {
        "cert_id": cert_id,
        "event_id": event_id,
        "recipient_name": recipient_name,
        "issued_at": issued_at,
        "data_hash": data_hash,
        "signature": signature_hex,
        "status": status,
        "lighthouse_cid": lighthouse_cid,
        "gateway_url": gateway_url,
        # Keep old field for backward compat
        "arweave_tx_id": lighthouse_cid,
    }
    save_registry(registry)

    return {
        "status": "SUCCESS", "payload": payload, "data_hash": data_hash,
        "signature": signature_hex, "lighthouse_cid": lighthouse_cid,
        "gateway_url": gateway_url, "arweave_tx_id": lighthouse_cid,
    }

# Pydantic models (same as before)
class CertificateRequest(BaseModel):
    cert_id: str; event_id: str; recipient_name: str; force: bool = False
class BatchRecord(BaseModel):
    recipient_name: str; cert_id: Optional[str] = None
class BatchIssueRequest(BaseModel):
    event_id: str; cert_prefix: str = "CERT"; records: List[BatchRecord]; force: bool = False
class PreprintBatchRequest(BaseModel):
    event_id: str; cert_prefix: str = "CERT"; quantity: int
class AssignRequest(BaseModel):
    recipient_name: str; force: bool = False
class AssignBatchRecord(BaseModel):
    cert_id: str; recipient_name: str
class AssignBatchRequest(BaseModel):
    records: List[AssignBatchRecord]; force: bool = False

@app.get("/health")
def health():
    return {
        "status": "ok",
        "signing_key_available": get_delegated_key_hex() is not None,
        "lighthouse_configured": get_lighthouse_key() is not None,
        "storage": "Lighthouse IPFS+Filecoin PERMANENT"
    }

@app.post("/api/v1/certificates/issue")
def issue_certificate(req: CertificateRequest):
    try:
        return sign_payload(req.cert_id, req.event_id, req.recipient_name, force=req.force)
    except SigningError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))

@app.post("/api/v1/certificates/batch-issue")
def batch_issue_certificates(req: BatchIssueRequest):
    if not req.records:
        raise HTTPException(status_code=400, detail="records must contain at least one entry.")
    issued, failed = [], []
    seen_ids_this_batch = set()
    next_auto_idx = _next_index_for_prefix(req.cert_prefix)
    for i, rec in enumerate(req.records, start=1):
        cert_id = rec.cert_id.strip() if rec.cert_id and rec.cert_id.strip() else f"{req.cert_prefix}-{next_auto_idx:03d}"
        if not rec.cert_id or not rec.cert_id.strip():
            next_auto_idx += 1
        if cert_id in seen_ids_this_batch:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": "Duplicate ID in batch"})
            continue
        seen_ids_this_batch.add(cert_id)
        try:
            signed = sign_payload(cert_id, req.event_id, rec.recipient_name, force=req.force)
            issued.append({"cert_id": cert_id, "payload": signed["payload"], "data_hash": signed["data_hash"], "signature": signed["signature"], "lighthouse_cid": signed.get("lighthouse_cid"), "gateway_url": signed.get("gateway_url")})
        except SigningError as e:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": str(e)})
    return {"total_requested": len(req.records), "total_issued": len(issued), "total_failed": len(failed), "certificates": issued, "failed": failed}

@app.post("/api/v1/certificates/preprint-batch")
def preprint_batch(req: PreprintBatchRequest):
    if req.quantity < 1 or req.quantity > 1000:
        raise HTTPException(status_code=400, detail="quantity must be 1-1000")
    created = []
    next_idx = _next_index_for_prefix(req.cert_prefix)
    for _ in range(req.quantity):
        cert_id = f"{req.cert_prefix}-{next_idx:03d}"; next_idx += 1
        try:
            signed = sign_payload(cert_id, req.event_id, PENDING_NAME_PLACEHOLDER, status="PENDING_ASSIGNMENT", archive=False)
            created.append({"cert_id": cert_id, "payload": signed["payload"]})
        except SigningError as e:
            created.append({"cert_id": cert_id, "error": str(e)})
    return {"total_requested": req.quantity, "certificates": created}

@app.post("/api/v1/certificates/{cert_id}/assign")
def assign_certificate(cert_id: str, req: AssignRequest):
    registry = load_registry()
    existing = registry.get(cert_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Certificate ID '{cert_id}' not found.")
    if existing.get("status") == "REVOKED" and not req.force:
        raise HTTPException(status_code=409, detail=f"Certificate '{cert_id}' is REVOKED")
    try:
        signed = sign_payload(cert_id, existing["event_id"], req.recipient_name, force=True, status="ACTIVE", archive=True)
    except SigningError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    return {"cert_id": cert_id, "payload": signed["payload"], "data_hash": signed["data_hash"], "signature": signed["signature"], "lighthouse_cid": signed.get("lighthouse_cid"), "gateway_url": signed.get("gateway_url")}

@app.post("/api/v1/certificates/assign-batch")
def assign_batch(req: AssignBatchRequest):
    if not req.records:
        raise HTTPException(status_code=400, detail="records must contain at least one entry.")
    registry = load_registry()
    assigned, failed = [], []
    for i, rec in enumerate(req.records, start=1):
        cert_id = (rec.cert_id or "").strip()
        existing = registry.get(cert_id)
        if not existing:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": f"ID '{cert_id}' not found."})
            continue
        if existing.get("status") == "REVOKED" and not req.force:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": "REVOKED"})
            continue
        try:
            signed = sign_payload(cert_id, existing["event_id"], rec.recipient_name, force=True, status="ACTIVE", archive=True)
            assigned.append({"cert_id": cert_id, "payload": signed["payload"], "data_hash": signed["data_hash"], "signature": signed["signature"], "lighthouse_cid": signed.get("lighthouse_cid"), "gateway_url": signed.get("gateway_url")})
            registry = load_registry()
        except SigningError as e:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": str(e)})
    return {"total_requested": len(req.records), "total_assigned": len(assigned), "total_failed": len(failed), "certificates": assigned, "failed": failed}

@app.get("/api/v1/certificates/pending")
def list_pending_certificates():
    registry = load_registry()
    return [{"cert_id": r["cert_id"], "event_id": r["event_id"], "issued_at": r["issued_at"]} for r in registry.values() if r.get("status") == "PENDING_ASSIGNMENT"]

@app.get("/api/v1/certificates/verify/{cert_id}")
def verify_certificate(cert_id: str):
    registry = load_registry()
    if cert_id not in registry:
        return {"found": False}
    record = registry[cert_id]
    return {
        "found": True, "cert_id": record["cert_id"], "event_id": record["event_id"],
        "recipient_name": record["recipient_name"], "issued_at": record["issued_at"],
        "data_hash": record["data_hash"], "signature": record["signature"],
        "status": record.get("status", "ACTIVE"),
        "lighthouse_cid": record.get("lighthouse_cid"),
        "gateway_url": record.get("gateway_url"),
        "arweave_tx_id": record.get("lighthouse_cid"), # backward compat
    }

@app.get("/api/v1/trust-root")
def trust_root():
    key_hex = get_delegated_key_hex()
    if not key_hex:
        raise HTTPException(status_code=500, detail="No signing key found.")
    signing_key = SigningKey(bytes.fromhex(key_hex))
    return {
        "key_id": "KEY-JSEAL-2026-01",
        "public_key_hex": signing_key.verify_key.encode().hex(),
        "algorithm": "Ed25519",
    }
