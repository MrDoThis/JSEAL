import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import List, Optional

import httpx
import nacl.encoding
import nacl.signing
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ============================================================
# JSeal Permanent API
# ============================================================

JSEAL_SIGNING_KEY = os.getenv("JSEAL_SIGNING_KEY", "").strip()
PINATA_JWT = os.getenv("PINATA_JWT", "").strip()

if not JSEAL_SIGNING_KEY:
    raise RuntimeError(
        "JSEAL_SIGNING_KEY is not configured. "
        "Set it as an environment variable in the backend host."
    )

try:
    signing_key = nacl.signing.SigningKey(
        JSEAL_SIGNING_KEY,
        encoder=nacl.encoding.HexEncoder,
    )
except Exception as exc:
    raise RuntimeError(
        "JSEAL_SIGNING_KEY must be a valid 64-character hexadecimal Ed25519 seed."
    ) from exc

verify_key = signing_key.verify_key
PUBLIC_HEX = verify_key.encode(
    encoder=nacl.encoding.HexEncoder
).decode()

app = FastAPI(
    title="JSeal Permanent API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary store.
# IMPORTANT: replace this with a persistent database before production.
DB: dict[str, dict] = {}


# ============================================================
# Helpers
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(payload: dict) -> str:
    """Must match the canonicalization used by the browser verifier."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )


def certificate_payload(
    cert_id: str,
    event_id: str,
    recipient_name: str,
    issued_at: str,
) -> dict:
    return {
        "cert_id": cert_id,
        "event_id": event_id,
        "recipient_name": recipient_name,
        "issued_at": issued_at,
    }


def sign_payload(payload: dict) -> tuple[str, str]:
    message = canonical(payload).encode("utf-8")
    signature = signing_key.sign(message).signature.hex()
    data_hash = hashlib.sha256(message).hexdigest()
    return signature, data_hash


def public_record(rec: dict) -> dict:
    """Shape returned to dashboards/verifiers."""
    return {
        "cert_id": rec["cert_id"],
        "event_id": rec["event_id"],
        "recipient_name": rec["recipient_name"],
        "issued_at": rec["issued_at"],
        "signature": rec["signature"],
        "data_hash": rec["data_hash"],
        "ipfs_cid": rec.get("ipfs_cid"),
        "lighthouse_cid": rec.get("ipfs_cid"),
        "permanent_url": rec.get("permanent_url"),
        "status": rec.get("status", "ACTIVE"),
    }


def build_bundle(rec: dict) -> dict:
    """Permanent JSON object stored on IPFS."""
    return {
        "jseal_version": "1.0",
        "certificate_id": rec["cert_id"],
        "payload": {
            "cert_id": rec["cert_id"],
            "event_id": rec["event_id"],
            "recipient_name": rec["recipient_name"],
            "issued_at": rec["issued_at"],
        },
        "hash": {
            "algorithm": "SHA-256",
            "digest_hex": rec["data_hash"],
        },
        "signature": {
            "algorithm": "Ed25519",
            "signature_hex": rec["signature"],
        },
        "ipfs_cid": rec.get("ipfs_cid"),
    }


async def pin_to_ipfs(cert_id: str, bundle: dict) -> Optional[str]:
    if not PINATA_JWT:
        return None

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.pinata.cloud/pinning/pinJSONToIPFS",
                headers={
                    "Authorization": f"Bearer {PINATA_JWT}",
                    "Content-Type": "application/json",
                },
                json={
                    "pinataContent": bundle,
                    "pinataMetadata": {"name": f"{cert_id}.json"},
                },
            )
            response.raise_for_status()
            return response.json().get("IpfsHash")
    except Exception as exc:
        print(f"[Pinata] Failed for {cert_id}: {exc}")
        return None


async def issue_certificate(
    cert_id: str,
    event_id: str,
    recipient_name: str,
    force: bool = False,
) -> dict:
    cert_id = cert_id.strip()
    event_id = event_id.strip()
    recipient_name = recipient_name.strip()

    if not cert_id:
        raise HTTPException(400, "cert_id is required")
    if not event_id:
        raise HTTPException(400, "event_id is required")
    if cert_id in DB and not force:
        raise HTTPException(
            400,
            f"{cert_id} already exists - use force=true to overwrite",
        )

    issued_at = utc_now()
    payload = certificate_payload(
        cert_id,
        event_id,
        recipient_name,
        issued_at,
    )

    signature, data_hash = sign_payload(payload)

    rec = {
        **payload,
        "signature": signature,
        "data_hash": data_hash,
        "ipfs_cid": None,
        "permanent_url": None,
        "status": "ACTIVE",
    }

    # Blank/pre-print certificates are allowed.
    # The signature covers the blank recipient_name and is re-signed on assignment.
    bundle = build_bundle(rec)
    cid = await pin_to_ipfs(cert_id, bundle)

    rec["ipfs_cid"] = cid
    rec["permanent_url"] = (
        f"https://gateway.pinata.cloud/ipfs/{cid}" if cid else None
    )

    DB[cert_id] = rec

    return {
        **public_record(rec),
        "payload": payload,
    }


# ============================================================
# Models
# ============================================================

class IssueReq(BaseModel):
    cert_id: str
    event_id: str
    recipient_name: str = ""
    force: bool = False


class BatchRecord(BaseModel):
    recipient_name: str = ""
    cert_id: Optional[str] = None


class BatchReq(BaseModel):
    event_id: str
    cert_prefix: str = "CERT"
    records: List[BatchRecord] = Field(default_factory=list)
    force: bool = False


class AssignReq(BaseModel):
    recipient_name: str


class AssignBatchRecord(BaseModel):
    cert_id: str
    recipient_name: str


class AssignBatchReq(BaseModel):
    records: List[AssignBatchRecord] = Field(default_factory=list)
    force: bool = False


# ============================================================
# Health / trust root
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "signing_key_available": True,
        "public_key_hex": PUBLIC_HEX,
        "pinata": bool(PINATA_JWT),
    }


@app.get("/api/v1/trust-root")
def trust_root():
    return {
        "public_key_hex": PUBLIC_HEX,
        "algorithm": "Ed25519",
    }


# ============================================================
# Certificate issuance
# ============================================================

@app.post("/api/v1/certificates/issue")
async def issue(req: IssueReq):
    return await issue_certificate(
        cert_id=req.cert_id,
        event_id=req.event_id,
        recipient_name=req.recipient_name,
        force=req.force,
    )


@app.post("/api/v1/certificates/batch-issue")
async def batch_issue(req: BatchReq):
    if not req.records:
        raise HTTPException(400, "records cannot be empty")

    certificates = []
    failed = []

    for index, row in enumerate(req.records):
        name = row.recipient_name.strip()
        cert_id = (
            row.cert_id.strip()
            if row.cert_id
            else f"{req.cert_prefix.strip()}-{int(time.time())}-{index}"
        )

        # Batch issuance requires names.
        if not name:
            failed.append({
                "recipient_name": "",
                "cert_id": cert_id,
                "reason": "missing recipient name",
            })
            continue

        try:
            result = await issue_certificate(
                cert_id=cert_id,
                event_id=req.event_id,
                recipient_name=name,
                force=req.force,
            )
            certificates.append(result)
        except HTTPException as exc:
            failed.append({
                "recipient_name": name,
                "cert_id": cert_id,
                "reason": str(exc.detail),
            })
        except Exception as exc:
            failed.append({
                "recipient_name": name,
                "cert_id": cert_id,
                "reason": str(exc),
            })

    return {
        "total_requested": len(req.records),
        "total_issued": len(certificates),
        "total_failed": len(failed),
        "certificates": certificates,
        "failed": failed,
    }


# ============================================================
# Pre-print blank certificates
# ============================================================

class PreprintReq(BaseModel):
    event_id: str
    cert_prefix: str
    quantity: int


@app.post("/api/v1/certificates/preprint-batch")
async def preprint_batch(req: PreprintReq):
    if req.quantity < 1 or req.quantity > 1000:
        raise HTTPException(400, "quantity must be between 1 and 1000")

    certificates = []
    failed = []

    for index in range(req.quantity):
        cert_id = f"{req.cert_prefix.strip()}-{int(time.time())}-{index}"

        try:
            result = await issue_certificate(
                cert_id=cert_id,
                event_id=req.event_id,
                recipient_name="",
                force=False,
            )
            certificates.append(result)

        except Exception as exc:
            failed.append({
                "recipient_name": "",
                "cert_id": cert_id,
                "reason": str(exc),
            })

    return {
        "total_requested": req.quantity,
        "total_issued": len(certificates),
        "total_failed": len(failed),
        "certificates": certificates,
        "failed": failed,
    }


# ============================================================
# Verification
# ============================================================

@app.get("/api/v1/certificates/verify/{cert_id}")
def verify(cert_id: str):
    rec = DB.get(cert_id)
    if not rec:
        return {
            "found": False,
            "cert_id": cert_id,
        }

    return {
        "found": True,
        **public_record(rec),
    }


@app.get("/api/v1/certificates/pending")
def pending():
    return [
        public_record(rec)
        for rec in DB.values()
        if not rec.get("recipient_name", "").strip()
    ]


# ============================================================
# Assignment
# ============================================================

@app.post("/api/v1/certificates/{cert_id}/assign")
async def assign(cert_id: str, body: AssignReq):
    cert_id = cert_id.strip()
    recipient_name = body.recipient_name.strip()

    if not recipient_name:
        raise HTTPException(400, "recipient_name is required")

    rec = DB.get(cert_id)
    if not rec:
        raise HTTPException(404, "certificate not found")

    if rec.get("status") == "REVOKED":
        raise HTTPException(400, "cannot assign a revoked certificate")

    # Keep the original certificate ID, event and issue time.
    payload = certificate_payload(
        cert_id=rec["cert_id"],
        event_id=rec["event_id"],
        recipient_name=recipient_name,
        issued_at=rec["issued_at"],
    )

    signature, data_hash = sign_payload(payload)

    rec.update({
        "recipient_name": recipient_name,
        "signature": signature,
        "data_hash": data_hash,
        "status": "ACTIVE",
    })

    # Re-pin the updated signed record.
    bundle = build_bundle(rec)
    cid = await pin_to_ipfs(cert_id, bundle)

    if cid:
        rec["ipfs_cid"] = cid
        rec["permanent_url"] = f"https://gateway.pinata.cloud/ipfs/{cid}"

    return {
        **public_record(rec),
        "payload": payload,
    }


@app.post("/api/v1/certificates/assign-batch")
async def assign_batch(req: AssignBatchReq):
    if not req.records:
        raise HTTPException(400, "records cannot be empty")

    certificates = []
    failed = []

    for row in req.records:
        cert_id = row.cert_id.strip()
        name = row.recipient_name.strip()

        if not cert_id or not name:
            failed.append({
                "cert_id": cert_id,
                "recipient_name": name,
                "reason": "certificate ID and recipient name are required",
            })
            continue

        try:
            result = await assign(
                cert_id,
                AssignReq(recipient_name=name),
            )
            certificates.append(result)
        except HTTPException as exc:
            failed.append({
                "cert_id": cert_id,
                "recipient_name": name,
                "reason": str(exc.detail),
            })
        except Exception as exc:
            failed.append({
                "cert_id": cert_id,
                "recipient_name": name,
                "reason": str(exc),
            })

    return {
        "total_requested": len(req.records),
        "total_assigned": len(certificates),
        "total_failed": len(failed),
        "certificates": certificates,
        "failed": failed,
    }
