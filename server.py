import os, hashlib, json, time
from datetime import datetime
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nacl.signing
import nacl.encoding
import httpx

# --- CONFIG ---
JSEAL_SIGNING_KEY = os.getenv("JSEAL_SIGNING_KEY", "").strip()
PINATA_JWT = os.getenv("PINATA_JWT", "").strip()

if not JSEAL_SIGNING_KEY:
    # Do NOT put a real key value in this message — it ends up in logs/error
    # pages. Generate one with: python -c "import nacl.signing,nacl.encoding as e;
    # print(nacl.signing.SigningKey.generate().encode(encoder=e.HexEncoder).decode())"
    raise RuntimeError(
        "JSEAL_SIGNING_KEY is not set. Set it in your environment "
        "(e.g. Render > Environment) to a 64-char hex Ed25519 signing key before starting the server."
    )

signing_key = nacl.signing.SigningKey(JSEAL_SIGNING_KEY.encode(), encoder=nacl.encoding.HexEncoder)
verify_key = signing_key.verify_key
PUBLIC_HEX = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

print(f"[JSeal] Public key: {PUBLIC_HEX}")
print(f"[JSeal] Pinata configured: {bool(PINATA_JWT)}")

app = FastAPI(title="JSeal Permanent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Simple in-memory store - replace with a real DB later if you want.
DB = {}


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def sign_payload(payload: dict):
    msg = canonical(payload).encode()
    sig = signing_key.sign(msg).signature
    data_hash = hashlib.sha256(msg).hexdigest()
    return sig.hex(), data_hash


async def pin_to_ipfs(cert_id: str, bundle: dict):
    if not PINATA_JWT:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.pinata.cloud/pinning/pinJSONToIPFS",
                headers={"Authorization": f"Bearer {PINATA_JWT}", "Content-Type": "application/json"},
                json={"pinataContent": bundle, "pinataMetadata": {"name": f"{cert_id}.json"}}
            )
            r.raise_for_status()
            return r.json()["IpfsHash"]
    except Exception as e:
        print(f"[Pinata] Failed {cert_id}: {e}")
        return None


# --- MODELS ---
class IssueReq(BaseModel):
    cert_id: str
    event_id: str
    recipient_name: str
    force: bool = False


class BatchReq(BaseModel):
    event_id: str
    cert_prefix: str = "CERT"
    records: List[dict]  # [{recipient_name, cert_id?}]
    force: bool = False
    allow_blank: bool = False  # preprint-batch needs nameless records to succeed


class AssignReq(BaseModel):
    recipient_name: str


class AssignRecord(BaseModel):
    cert_id: str
    recipient_name: str


class AssignBatchReq(BaseModel):
    records: List[AssignRecord]
    force: bool = False


class PreprintReq(BaseModel):
    event_id: str
    cert_prefix: str = "CERT"
    quantity: int = 1


# --- ROUTES ---
@app.get("/health")
def health():
    return {
        "status": "ok",
        "signing_key_available": True,
        "public_key_hex": PUBLIC_HEX,
        "pinata": bool(PINATA_JWT)
    }


@app.get("/api/v1/trust-root")
def trust_root():
    return {"public_key_hex": PUBLIC_HEX, "algorithm": "Ed25519"}


@app.post("/api/v1/certificates/issue")
async def issue(req: IssueReq):
    if req.cert_id in DB and not req.force:
        raise HTTPException(400, f"{req.cert_id} already exists - use force=true to overwrite")

    payload = {
        "cert_id": req.cert_id,
        "event_id": req.event_id,
        "recipient_name": req.recipient_name,
        "issued_at": datetime.utcnow().isoformat() + "Z"
    }
    sig_hex, data_hash = sign_payload(payload)

    bundle = {
        "jseal_version": "1.0",
        "certificate_id": req.cert_id,
        "payload": payload,
        "hash": {"algorithm": "SHA-256", "digest_hex": data_hash},
        "signature": {"algorithm": "Ed25519", "signature_hex": sig_hex}
    }

    cid = await pin_to_ipfs(req.cert_id, bundle)
    bundle["ipfs_cid"] = cid
    bundle["permanent_url"] = f"https://gateway.pinata.cloud/ipfs/{cid}" if cid else None
    bundle["arweave_tx_id"] = cid  # keep frontend compat - it uses this field for the verify url

    DB[req.cert_id] = {**payload, "signature": sig_hex, "data_hash": data_hash, "ipfs_cid": cid, "status": "ACTIVE"}

    return {
        "cert_id": req.cert_id,
        "payload": payload,
        "data_hash": data_hash,
        "signature": sig_hex,
        "arweave_tx_id": cid,
        "ipfs_cid": cid,
        "permanent_url": bundle["permanent_url"]
    }


@app.get("/api/v1/certificates/verify/{cert_id}")
def verify(cert_id: str):
    rec = DB.get(cert_id)
    if not rec:
        return {"found": False, "cert_id": cert_id}
    return {"found": True, **rec}


@app.get("/api/v1/certificates/pending")
def pending():
    return [v for v in DB.values() if not v.get("recipient_name")]


@app.post("/api/v1/certificates/batch-issue")
async def batch_issue(req: BatchReq):
    certs = []
    failed = []
    for i, r in enumerate(req.records):
        name = r.get("recipient_name", "").strip()
        cid = r.get("cert_id") or f"{req.cert_prefix}-{int(time.time())}-{i}"
        if not name and not req.allow_blank:
            failed.append({"recipient_name": name, "cert_id": cid, "reason": "missing name"})
            continue
        try:
            res = await issue(IssueReq(cert_id=cid, event_id=req.event_id, recipient_name=name, force=req.force))
            certs.append(res)
        except Exception as e:
            failed.append({"recipient_name": name, "cert_id": cid, "reason": str(e)})
    return {"total_requested": len(req.records), "total_issued": len(certs), "total_failed": len(failed), "certificates": certs, "failed": failed}


@app.post("/api/v1/certificates/preprint-batch")
async def preprint_batch(req: PreprintReq):
    # FIX: this used to take (event_id: str, cert_prefix: str, quantity: int) as bare
    # params, which makes FastAPI expect them as query-string params. The frontend
    # sends a JSON body, so every call 422'd. A Pydantic body model fixes that.
    return await batch_issue(BatchReq(
        event_id=req.event_id,
        cert_prefix=req.cert_prefix,
        records=[{"recipient_name": ""} for _ in range(req.quantity)],
        allow_blank=True
    ))


@app.post("/api/v1/certificates/{cert_id}/assign")
async def assign(cert_id: str, body: AssignReq):
    rec = DB.get(cert_id)
    if not rec:
        raise HTTPException(404, "not found")
    rec["recipient_name"] = body.recipient_name
    payload = {"cert_id": rec["cert_id"], "event_id": rec["event_id"], "recipient_name": body.recipient_name, "issued_at": rec["issued_at"]}
    sig, h = sign_payload(payload)
    rec["signature"] = sig
    rec["data_hash"] = h
    return {"payload": payload, "data_hash": h, "signature": sig, "arweave_tx_id": rec.get("ipfs_cid")}


@app.post("/api/v1/certificates/assign-batch")
async def assign_batch(req: AssignBatchReq):
    # FIX: the admin dashboard's "Assign From File" flow calls this exact path,
    # but the route never existed on the backend — every bulk assignment 404'd.
    certs = []
    failed = []
    for r in req.records:
        rec = DB.get(r.cert_id)
        if not rec:
            failed.append({"recipient_name": r.recipient_name, "cert_id": r.cert_id, "reason": "certificate ID not found"})
            continue
        if rec.get("status") == "REVOKED" and not req.force:
            failed.append({"recipient_name": r.recipient_name, "cert_id": r.cert_id, "reason": "certificate is REVOKED - enable override to reassign"})
            continue
        try:
            res = await assign(r.cert_id, AssignReq(recipient_name=r.recipient_name))
            certs.append({"cert_id": r.cert_id, **res})
        except Exception as e:
            failed.append({"recipient_name": r.recipient_name, "cert_id": r.cert_id, "reason": str(e)})
    return {"total_requested": len(req.records), "total_assigned": len(certs), "total_failed": len(failed), "certificates": certs, "failed": failed}
