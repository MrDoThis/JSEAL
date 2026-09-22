import os
import json
import hashlib
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from nacl.signing import SigningKey

import arweave_client

app = FastAPI(title="JSeal Secure Certification Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REGISTRY_FILE = "jseal_registry.json"
KEY_MANIFEST_FILE = "jseal_key_manifest.json"


def get_delegated_key_hex():
    """1. JSEAL_DELEGATED_KEY_HEX env var (production).
    2. jseal_key_manifest.json in this folder (local dev convenience).
    Never commit that file or upload it anywhere — it holds a real private key."""
    key_hex = os.getenv("JSEAL_DELEGATED_KEY_HEX")
    if key_hex:
        return key_hex
    if os.path.exists(KEY_MANIFEST_FILE):
        try:
            with open(KEY_MANIFEST_FILE, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            print(f"[dev-mode] Falling back to {KEY_MANIFEST_FILE}. Set JSEAL_DELEGATED_KEY_HEX for production.")
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
    """Carries an HTTP status code so callers (single-issue route, or the
    batch loop) can decide whether to abort or just record the failure and
    keep going."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


PENDING_NAME_PLACEHOLDER = "PENDING_ASSIGNMENT"


def _next_index_for_prefix(prefix: str) -> int:
    """Scans the registry for existing IDs like '{prefix}-###' and returns
    the next free number. Without this, two separate batches (or a batch
    run twice) with the same prefix would both try to start at -001 and
    collide — this makes numbering continue where it left off instead."""
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
        raise SigningError(
            f"No signing key found. Set JSEAL_DELEGATED_KEY_HEX, or place "
            f"{KEY_MANIFEST_FILE} (from keygen.py) in this folder.",
            500,
        )

    registry = load_registry()
    if cert_id in registry and not force:
        raise SigningError(
            f"Certificate ID '{cert_id}' already exists (issued {registry[cert_id].get('issued_at', '?')} "
            f"to {registry[cert_id].get('recipient_name', '?')}). Re-issuing would overwrite a real record — "
            f"use a different ID, or explicitly confirm overwrite.",
            409,
        )

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

    # Optional permanent archival (architecture Phase 2). Skipped entirely
    # for pending/blank pre-prints — archiving a placeholder name would
    # leave a permanent, immutable "PENDING_ASSIGNMENT" copy on Arweave
    # even after a real name is assigned later. Only the finalized content
    # (from /issue or /assign) gets archived. Disabled unless
    # ARWEAVE_ENABLED + ARWEAVE_WALLET_PATH are configured; a failure or
    # timeout here never blocks issuance.
    arweave_tx_id = None
    if archive:
        bundle = {
            "jseal_version": "1.0",
            "certificate_id": cert_id,
            "payload": payload,
            "hash": {"algorithm": "SHA-256", "digest_hex": data_hash},
            "signature": {"algorithm": "Ed25519", "signature_hex": signature_hex},
        }
        arweave_tx_id = arweave_client.upload_bundle(cert_id, bundle)

    registry[cert_id] = {
        "cert_id": cert_id,
        "event_id": event_id,
        "recipient_name": recipient_name,
        "issued_at": issued_at,
        "data_hash": data_hash,
        "signature": signature_hex,
        "status": status,
        "arweave_tx_id": arweave_tx_id,
    }
    save_registry(registry)

    return {
        "status": "SUCCESS", "payload": payload, "data_hash": data_hash,
        "signature": signature_hex, "arweave_tx_id": arweave_tx_id,
    }


class CertificateRequest(BaseModel):
    cert_id: str
    event_id: str
    recipient_name: str
    force: bool = False


class BatchRecord(BaseModel):
    recipient_name: str
    cert_id: Optional[str] = None


class BatchIssueRequest(BaseModel):
    event_id: str
    cert_prefix: str = "CERT"
    records: List[BatchRecord]
    force: bool = False


class PreprintBatchRequest(BaseModel):
    event_id: str
    cert_prefix: str = "CERT"
    quantity: int


class AssignRequest(BaseModel):
    recipient_name: str
    force: bool = False


class AssignBatchRecord(BaseModel):
    cert_id: str
    recipient_name: str


class AssignBatchRequest(BaseModel):
    records: List[AssignBatchRecord]
    force: bool = False


@app.get("/health")
def health():
    """A real health check — the frontend's connection banner is only as
    honest as this endpoint. It reports whether a signing key is actually
    available, not just whether the process is running."""
    key_available = get_delegated_key_hex() is not None
    return {"status": "ok", "signing_key_available": key_available}


@app.post("/api/v1/certificates/issue")
def issue_certificate(req: CertificateRequest):
    try:
        return sign_payload(req.cert_id, req.event_id, req.recipient_name, force=req.force)
    except SigningError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


@app.post("/api/v1/certificates/batch-issue")
def batch_issue_certificates(req: BatchIssueRequest):
    """Processes every row even if some fail. A batch of 50 where row 17 has
    a blank name or a duplicate ID no longer aborts the other 49 — it signs
    everything it can and reports exactly what it couldn't, and why."""
    if not req.records:
        raise HTTPException(status_code=400, detail="records must contain at least one entry.")

    issued, failed = [], []
    seen_ids_this_batch = set()
    next_auto_idx = _next_index_for_prefix(req.cert_prefix)

    for i, rec in enumerate(req.records, start=1):
        if rec.cert_id and rec.cert_id.strip():
            cert_id = rec.cert_id.strip()
        else:
            cert_id = f"{req.cert_prefix}-{next_auto_idx:03d}"
            next_auto_idx += 1

        if cert_id in seen_ids_this_batch:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name,
                            "reason": "Duplicate certificate ID within this same batch."})
            continue
        seen_ids_this_batch.add(cert_id)

        try:
            signed = sign_payload(cert_id, req.event_id, rec.recipient_name, force=req.force)
            issued.append({"cert_id": cert_id, "payload": signed["payload"],
                            "data_hash": signed["data_hash"], "signature": signed["signature"],
                            "arweave_tx_id": signed.get("arweave_tx_id")})
        except SigningError as e:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": str(e)})

    return {
        "total_requested": len(req.records),
        "total_issued": len(issued),
        "total_failed": len(failed),
        "certificates": issued,
        "failed": failed,
    }


@app.post("/api/v1/certificates/preprint-batch")
def preprint_batch(req: PreprintBatchRequest):
    """Generates blank, already-signed certificates ahead of time — cert
    number and QR are real and valid immediately, but the recipient name is
    a placeholder until someone assigns a real name later via /assign or
    /assign-batch. The certificate ID never changes between pre-print and
    assignment, so a QR code printed now stays correct forever."""
    if req.quantity < 1 or req.quantity > 1000:
        raise HTTPException(status_code=400, detail="quantity must be between 1 and 1000.")

    created = []
    next_idx = _next_index_for_prefix(req.cert_prefix)
    for _ in range(req.quantity):
        cert_id = f"{req.cert_prefix}-{next_idx:03d}"
        next_idx += 1
        try:
            signed = sign_payload(cert_id, req.event_id, PENDING_NAME_PLACEHOLDER,
                                   status="PENDING_ASSIGNMENT", archive=False)
            created.append({"cert_id": cert_id, "payload": signed["payload"]})
        except SigningError as e:
            # Extremely unlikely (would mean a collision even after
            # scanning the registry), but don't let one bad row kill the
            # rest of the batch.
            created.append({"cert_id": cert_id, "error": str(e)})

    return {"total_requested": req.quantity, "certificates": created}


@app.post("/api/v1/certificates/{cert_id}/assign")
def assign_certificate(cert_id: str, req: AssignRequest):
    """Attaches a real recipient name to a certificate ID — whether that ID
    was pre-printed blank, or already active and needs correcting. Re-signs
    with the real name and archives the FINAL content to Arweave (pending
    placeholders are never archived — see sign_payload). The certificate ID
    itself never changes, so any QR code already printed for this ID keeps
    working without modification."""
    registry = load_registry()
    existing = registry.get(cert_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Certificate ID '{cert_id}' not found.")
    if existing.get("status") == "REVOKED" and not req.force:
        raise HTTPException(
            status_code=409,
            detail=f"Certificate '{cert_id}' is REVOKED. Assigning a new name would silently "
                    "un-revoke it — pass force=true if that's really intended.",
        )

    try:
        signed = sign_payload(cert_id, existing["event_id"], req.recipient_name,
                               force=True, status="ACTIVE", archive=True)
    except SigningError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))

    return {"cert_id": cert_id, "payload": signed["payload"], "data_hash": signed["data_hash"],
            "signature": signed["signature"], "arweave_tx_id": signed.get("arweave_tx_id")}


@app.post("/api/v1/certificates/assign-batch")
def assign_batch(req: AssignBatchRequest):
    """Bulk version of /assign — for uploading a CSV/XLSX of CertificateID,
    Name pairs once names are known. Every row is attempted even if some
    fail (unknown ID, revoked without force), and every outcome is reported
    individually rather than aborting the whole batch."""
    if not req.records:
        raise HTTPException(status_code=400, detail="records must contain at least one entry.")

    registry = load_registry()
    assigned, failed = [], []

    for i, rec in enumerate(req.records, start=1):
        cert_id = (rec.cert_id or "").strip()
        existing = registry.get(cert_id)
        if not existing:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name,
                            "reason": f"Certificate ID '{cert_id}' not found."})
            continue
        if existing.get("status") == "REVOKED" and not req.force:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name,
                            "reason": "Certificate is REVOKED — use force to un-revoke and reassign."})
            continue
        try:
            signed = sign_payload(cert_id, existing["event_id"], rec.recipient_name,
                                   force=True, status="ACTIVE", archive=True)
            assigned.append({"cert_id": cert_id, "payload": signed["payload"],
                              "data_hash": signed["data_hash"], "signature": signed["signature"],
                              "arweave_tx_id": signed.get("arweave_tx_id")})
            registry = load_registry()  # refresh so subsequent rows see updated state
        except SigningError as e:
            failed.append({"row": i, "cert_id": cert_id, "recipient_name": rec.recipient_name, "reason": str(e)})

    return {
        "total_requested": len(req.records),
        "total_assigned": len(assigned),
        "total_failed": len(failed),
        "certificates": assigned,
        "failed": failed,
    }


@app.get("/api/v1/certificates/pending")
def list_pending_certificates():
    """Lists blank, pre-printed certificate IDs still waiting for a name —
    what the admin UI's assignment dropdown is populated from."""
    registry = load_registry()
    return [
        {"cert_id": r["cert_id"], "event_id": r["event_id"], "issued_at": r["issued_at"]}
        for r in registry.values() if r.get("status") == "PENDING_ASSIGNMENT"
    ]


@app.get("/api/v1/certificates/verify/{cert_id}")
def verify_certificate(cert_id: str):
    registry = load_registry()
    if cert_id not in registry:
        return {"found": False}
    record = registry[cert_id]
    return {
        "found": True,
        "cert_id": record["cert_id"],
        "event_id": record["event_id"],
        "recipient_name": record["recipient_name"],
        "issued_at": record["issued_at"],
        "data_hash": record["data_hash"],
        "signature": record["signature"],
        "status": record.get("status", "ACTIVE"),
        "arweave_tx_id": record.get("arweave_tx_id"),
    }


@app.post("/api/v1/certificates/{cert_id}/revoke")
def revoke_certificate(cert_id: str):
    registry = load_registry()
    if cert_id not in registry:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    registry[cert_id]["status"] = "REVOKED"
    save_registry(registry)
    return {"cert_id": cert_id, "status": "REVOKED"}


@app.get("/api/v1/trust-root")
def trust_root():
    """Publishes the public key corresponding to whatever private key is
    actually loaded right now. The frontend fetches this instead of
    hardcoding a key string — a hardcoded key that drifts out of sync with
    the real signing key is what caused SIGNATURE MISMATCH earlier.

    This is a convenience for the LIVE verification page only. It does not
    replace the permanent, multi-channel trust-root distribution (printed
    on the certificate, OpenTimestamps, Internet Archive) needed for
    verification once this server no longer exists."""
    key_hex = get_delegated_key_hex()
    if not key_hex:
        raise HTTPException(status_code=500, detail="No signing key found.")
    signing_key = SigningKey(bytes.fromhex(key_hex))
    return {
        "key_id": "KEY-JSEAL-2026-01",
        "public_key_hex": signing_key.verify_key.encode().hex(),
        "algorithm": "Ed25519",
    }
