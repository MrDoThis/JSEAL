import os, hashlib, json, time
from datetime import datetime
from typing import List, Optional
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
    raise RuntimeError("JSEAL_SIGNING_KEY not set - set it to a7b00f86d595f134f7b76b049955631b50eaa46fced4963b9c22cfea61a6d1a1")

signing_key = nacl.signing.SigningKey(JSEAL_SIGNING_KEY.encode(), encoder=nacl.encoding.HexEncoder)
verify_key = signing_key.verify_key
PUBLIC_HEX = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

print(f"[JSeal] Public key: {PUBLIC_HEX}")
print(f"[JSeal] Pinata configured: {bool(PINATA_JWT)}")

app = FastAPI(title="JSeal Permanent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Simple in-memory store - replace with DB later if you want
DB = {}

def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',',':'))

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
            cid = r.json()["IpfsHash"]
            return cid
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
    records: List[dict] # [{recipient_name, cert_id?}]
    force: bool = False

class AssignReq(BaseModel):
    recipient_name: str

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
    bundle["arweave_tx_id"] = cid # keep frontend compat - it uses this field for verify url

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
        name = r.get("recipient_name","").strip()
        cid = r.get("cert_id") or f"{req.cert_prefix}-{int(time.time())}-{i}"
        if not name:
            failed.append({"recipient_name": name, "cert_id": cid, "reason": "missing name"})
            continue
        try:
            res = await issue(IssueReq(cert_id=cid, event_id=req.event_id, recipient_name=name, force=req.force))
            certs.append(res)
        except Exception as e:
            failed.append({"recipient_name": name, "cert_id": cid, "reason": str(e)})
    return {"total_requested": len(req.records), "total_issued": len(certs), "total_failed": len(failed), "certificates": certs, "failed": failed}

# --- minimal assign routes for your preprint flow ---
@app.post("/api/v1/certificates/preprint-batch")
async def preprint_batch(event_id: str, cert_prefix: str, quantity: int):
    # body as json
    return await batch_issue(BatchReq(event_id=event_id, cert_prefix=cert_prefix, records=[{"recipient_name": ""} for _ in range(quantity)]))

@app.post("/api/v1/certificates/{cert_id}/assign")
async def assign(cert_id: str, body: AssignReq):
    rec = DB.get(cert_id)
    if not rec:
        raise HTTPException(404, "not found")
    rec["recipient_name"] = body.recipient_name
    # re-sign
    payload = {"cert_id": rec["cert_id"], "event_id": rec["event_id"], "recipient_name": body.recipient_name, "issued_at": rec["issued_at"]}
    sig, h = sign_payload(payload)
    rec["signature"] = sig
    rec["data_hash"] = h
    return {"payload": payload, "data_hash": h, "signature": sig, "arweave_tx_id": rec.get("ipfs_cid")}
