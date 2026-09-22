import os
import json
import uuid
import hashlib
import tempfile
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nacl.signing
import nacl.encoding

app = FastAPI(title="JSeal Certificate Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Persistence — a flat JSON file. Fine for a single instance; if you outgrow
# it (or your host wipes disk on redeploy, e.g. Render free tier), swap this
# for Postgres/SQLite on a persistent volume.
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("JSEAL_DB_PATH", "certificates_db.json")


def _load_db():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_db():
    with open(DB_PATH, "w") as f:
        json.dump(certificates_db, f, indent=2)


certificates_db = _load_db()  # cert_id -> record dict

# ---------------------------------------------------------------------------
# Signing key (Ed25519, via PyNaCl — wire-compatible with tweetnacl-js,
# which is what both HTML pages use to verify).
#
# Resolution order:
#   1. JSEAL_SIGNING_KEY env var (64-char hex seed) — use this in production
#      so the key survives redeploys and matches whatever you hardcode into
#      verify-standalone.html.
#   2. A local signing_key.hex file — persists across restarts as long as
#      disk persists, but NOT across a redeploy on ephemeral hosts.
#   3. Freshly generated at startup as a last resort (logged loudly, since
#      every certificate signed before a restart becomes unverifiable).
# ---------------------------------------------------------------------------
SIGNING_KEY_PATH = os.getenv("JSEAL_SIGNING_KEY_PATH", "signing_key.hex")
_signing_key = None
_signing_key_is_persistent = False


def _load_or_create_signing_key():
    global _signing_key, _signing_key_is_persistent

    env_seed = os.getenv("JSEAL_SIGNING_KEY")
    if env_seed:
        _signing_key = nacl.signing.SigningKey(bytes.fromhex(env_seed.strip()))
        _signing_key_is_persistent = True
        print("[JSeal] Signing key loaded from JSEAL_SIGNING_KEY env var.")
        return

    if os.path.exists(SIGNING_KEY_PATH):
        with open(SIGNING_KEY_PATH, "r") as f:
            _signing_key = nacl.signing.SigningKey(bytes.fromhex(f.read().strip()))
        _signing_key_is_persistent = True
        print(f"[JSeal] Signing key loaded from {SIGNING_KEY_PATH}.")
        return

    _signing_key = nacl.signing.SigningKey.generate()
    try:
        with open(SIGNING_KEY_PATH, "w") as f:
            f.write(_signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
        _signing_key_is_persistent = True
        print(f"[JSeal] No signing key found — generated a new one and saved it to {SIGNING_KEY_PATH}.")
    except Exception:
        _signing_key_is_persistent = False
        print("[JSeal] WARNING: generated an ephemeral signing key and could not persist it to disk. "
              "All certificates will become unverifiable on restart. Set JSEAL_SIGNING_KEY.")

    print(f"[JSeal] Public key (hex): {_signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()}")
    print("[JSeal] If this is a fresh key, update PUBLIC_KEY_HEX in verify-standalone.html to match.")


_load_or_create_signing_key()


def get_public_key_hex() -> str:
    return _signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()


def canonicalize(payload: dict) -> str:
    # Must match the frontend's canonicalize(): JSON.stringify(sorted keys),
    # no extra whitespace.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_payload(payload: dict):
    message = canonicalize(payload).encode("utf-8")
    data_hash = hashlib.sha256(message).hexdigest()
    signed = _signing_key.sign(message)
    return data_hash, signed.signature.hex()


# ---------------------------------------------------------------------------
# Lighthouse (IPFS + Filecoin permanent storage), via the official SDK.
# ---------------------------------------------------------------------------
try:
    from lighthouseweb3 import Lighthouse
    _lh_sdk_available = True
except ImportError:
    _lh_sdk_available = False


def lighthouse_configured() -> bool:
    return bool(os.getenv("LIGHTHOUSE_API_KEY")) and _lh_sdk_available


def build_lighthouse_bundle(cert_id, payload, data_hash, signature_hex):
    # Shape must match what verify-standalone.html's tryLighthouse() parses:
    # bundle.certificate_id, bundle.payload.*, bundle.signature.signature_hex
    return {
        "jseal_version": "1.0",
        "certificate_id": cert_id,
        "payload": payload,
        "hash": {"algorithm": "SHA-256", "digest_hex": data_hash},
        "signature": {"algorithm": "Ed25519", "signature_hex": signature_hex},
    }


def upload_to_lighthouse(bundle: dict, cert_id: str) -> Optional[str]:
    api_key = os.getenv("LIGHTHOUSE_API_KEY")
    if not api_key or not _lh_sdk_available:
        return None
    tmp_path = None
    try:
        lh = Lighthouse(token=api_key)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(bundle, tmp)
            tmp_path = tmp.name
        result = lh.upload(tmp_path)
        cid = None
        if isinstance(result, dict):
            cid = result.get("data", {}).get("Hash")
        if cid:
            print(f"[Lighthouse] {cert_id} -> {cid}")
        else:
            print(f"[Lighthouse] Unexpected response for {cert_id}: {result}")
        return cid
    except Exception as e:
        print(f"[Lighthouse] Upload failed for {cert_id}: {e}")
        return None
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Models — shaped to match what the dashboard actually sends.
# ---------------------------------------------------------------------------
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _issue_or_sign(cert_id: str, event_id: str, recipient_name: str):
    """Sign (or re-sign) a certificate and persist it. Used by issue,
    batch-issue, and both assign paths so every certificate is produced
    the same way."""
    issued_at = now_iso()
    payload = {
        "cert_id": cert_id,
        "event_id": event_id,
        "issued_at": issued_at,
        "recipient_name": recipient_name,
    }
    data_hash, signature_hex = sign_payload(payload)
    bundle = build_lighthouse_bundle(cert_id, payload, data_hash, signature_hex)
    cid = upload_to_lighthouse(bundle, cert_id)

    certificates_db[cert_id] = {
        "cert_id": cert_id,
        "event_id": event_id,
        "recipient_name": recipient_name,
        "issued_at": issued_at,
        "status": "ACTIVE",
        "data_hash": data_hash,
        "signature": signature_hex,
        "lighthouse_cid": cid,
    }
    _save_db()
    return payload, data_hash, signature_hex, cid


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "signing_key_available": _signing_key is not None,
        "signing_key_persistent": _signing_key_is_persistent,
        "lighthouse_configured": lighthouse_configured(),
        "total_certificates": len(certificates_db),
    }


@app.get("/api/v1/trust-root")
def trust_root():
    return {"issuer": "JSEAL", "algorithm": "Ed25519", "public_key_hex": get_public_key_hex()}


@app.post("/api/v1/certificates/issue")
def issue_certificate(req: IssueRequest):
    existing = certificates_db.get(req.cert_id)
    if existing and existing.get("status") != "PENDING" and not req.force:
        raise HTTPException(
            status_code=409,
            detail=f"Certificate ID '{req.cert_id}' already exists. Enable overwrite to replace it.",
        )
    payload, data_hash, signature_hex, cid = _issue_or_sign(req.cert_id, req.event_id, req.recipient_name)
    return {
        "cert_id": req.cert_id,
        "payload": payload,
        "data_hash": data_hash,
        "signature": signature_hex,
        "arweave_tx_id": cid,  # holds the Lighthouse CID — see note in README
    }


@app.post("/api/v1/certificates/batch-issue")
def batch_issue(req: BatchIssueRequest):
    issued, failed = [], []
    for rec in req.records:
        cert_id = rec.cert_id or f"{req.cert_prefix}-{uuid.uuid4().hex[:8]}"
        existing = certificates_db.get(cert_id)
        if existing and existing.get("status") != "PENDING" and not req.force:
            failed.append({"recipient_name": rec.recipient_name, "cert_id": cert_id, "reason": "Certificate ID already exists"})
            continue
        try:
            payload, data_hash, signature_hex, cid = _issue_or_sign(cert_id, req.event_id, rec.recipient_name)
            issued.append({"cert_id": cert_id, "payload": payload, "data_hash": data_hash, "signature": signature_hex, "arweave_tx_id": cid})
        except Exception as e:
            failed.append({"recipient_name": rec.recipient_name, "cert_id": cert_id, "reason": str(e)})
    return {
        "total_requested": len(req.records),
        "total_issued": len(issued),
        "total_failed": len(failed),
        "certificates": issued,
        "failed": failed,
    }


@app.post("/api/v1/certificates/preprint-batch")
def preprint_batch(req: PreprintRequest):
    created = []
    for _ in range(req.quantity):
        cert_id = f"{req.cert_prefix}-{uuid.uuid4().hex[:8]}"
        while cert_id in certificates_db:
            cert_id = f"{req.cert_prefix}-{uuid.uuid4().hex[:8]}"
        certificates_db[cert_id] = {
            "cert_id": cert_id,
            "event_id": req.event_id,
            "recipient_name": None,
            "issued_at": None,
            "status": "PENDING",
            "data_hash": None,
            "signature": None,
            "lighthouse_cid": None,
        }
        created.append({"cert_id": cert_id})
    _save_db()
    return {"total_requested": req.quantity, "certificates": created}


@app.get("/api/v1/certificates/pending")
def pending():
    return [
        {"cert_id": c["cert_id"], "event_id": c["event_id"]}
        for c in certificates_db.values()
        if c.get("status") == "PENDING"
    ]


@app.post("/api/v1/certificates/{cert_id}/assign")
def assign_single(cert_id: str, req: AssignRequest):
    record = certificates_db.get(cert_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
    if record.get("status") != "PENDING":
        raise HTTPException(status_code=400, detail=f"Certificate '{cert_id}' is not pending (status: {record.get('status')}).")
    payload, data_hash, signature_hex, cid = _issue_or_sign(cert_id, record["event_id"], req.recipient_name)
    return {"cert_id": cert_id, "payload": payload, "data_hash": data_hash, "signature": signature_hex, "arweave_tx_id": cid}


@app.post("/api/v1/certificates/assign-batch")
def assign_batch(req: AssignBatchRequest):
    assigned, failed = [], []
    for rec in req.records:
        record = certificates_db.get(rec.cert_id)
        if not record:
            failed.append({"cert_id": rec.cert_id, "recipient_name": rec.recipient_name, "reason": "not found"})
            continue
        status = record.get("status")
        if status == "ACTIVE" and not req.force:
            failed.append({"cert_id": rec.cert_id, "recipient_name": rec.recipient_name, "reason": "already assigned"})
            continue
        if status == "REVOKED" and not req.force:
            failed.append({"cert_id": rec.cert_id, "recipient_name": rec.recipient_name, "reason": "revoked — enable overwrite to reassign"})
            continue
        try:
            payload, data_hash, signature_hex, cid = _issue_or_sign(rec.cert_id, record["event_id"], rec.recipient_name)
            assigned.append({"cert_id": rec.cert_id, "payload": payload, "data_hash": data_hash, "signature": signature_hex, "arweave_tx_id": cid})
        except Exception as e:
            failed.append({"cert_id": rec.cert_id, "recipient_name": rec.recipient_name, "reason": str(e)})
    return {
        "total_requested": len(req.records),
        "total_assigned": len(assigned),
        "total_failed": len(failed),
        "certificates": assigned,
        "failed": failed,
    }


@app.get("/api/v1/certificates/verify/{cert_id}")
def verify(cert_id: str):
    record = certificates_db.get(cert_id)
    if not record:
        return {"found": False}
    return {
        "found": True,
        "cert_id": record["cert_id"],
        "event_id": record["event_id"],
        "issued_at": record.get("issued_at"),
        "recipient_name": record.get("recipient_name"),
        "signature": record.get("signature"),
        "status": record.get("status"),
        "lighthouse_cid": record.get("lighthouse_cid"),
    }


@app.post("/api/v1/certificates/{cert_id}/revoke")
def revoke(cert_id: str):
    record = certificates_db.get(cert_id)
    if not record:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    record["status"] = "REVOKED"
    certificates_db[cert_id] = record
    _save_db()
    return {"cert_id": cert_id, "status": "REVOKED"}


@app.get("/")
def root():
    return {"status": "JSeal backend live", "public_key_hex": get_public_key_hex()}
