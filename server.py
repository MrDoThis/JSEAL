import os
import json
import base64
import requests
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage
certificates_db = {}
trust_root = {
    "public_key": "YOUR_PUBLIC_KEY_HERE",
    "issuer": "JSEAL"
}

class IssueRequest(BaseModel):
    name: str
    certificate_id: str
    event_id: str

LIGHTHOUSE_API_URL = "https://node.lighthouse.storage/api/v0/add"

def upload_to_lighthouse(cert_data: dict, cert_id: str):
    api_key = os.getenv("LIGHTHOUSE_API_KEY") or os.getenv("LIGHTHOUSE_AUTH_KEY")
    if not api_key:
        print("[Lighthouse] No API key set")
        return None
    try:
        api_key = api_key.strip()
        json_bytes = json.dumps(cert_data).encode('utf-8')
        files = {'file': (f'{cert_id}.json', json_bytes, 'application/json')}
        headers = {'Authorization': f'Bearer {api_key}'}
        resp = requests.post(LIGHTHOUSE_API_URL, files=files, headers=headers, timeout=60)
        resp.raise_for_status()
        result = resp.json()
        cid = result.get('Hash')
        if cid:
            print(f"[Lighthouse] SUCCESS {cert_id} -> CID: {cid}")
            return cid
        print(f"[Lighthouse] Response no Hash: {result}")
        return None
    except Exception as e:
        print(f"[Lighthouse] Upload failed for {cert_id}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"[Lighthouse] Response text: {e.response.text[:500]}")
        return None

@app.get("/health")
def health():
    has_key = bool(os.getenv("LIGHTHOUSE_API_KEY") or os.getenv("LIGHTHOUSE_AUTH_KEY"))
    return {
        "status": "ok",
        "lighthouse_configured": has_key,
        "total_certs": len(certificates_db)
    }

@app.get("/")
def root():
    return {"status": "JSEAL backend live"}

@app.post("/api/v1/certificates/issue")
def issue_certificate(req: IssueRequest):
    # Create certificate payload
    cert_data = {
        "certificate_id": req.certificate_id,
        "name": req.name,
        "event_id": req.event_id,
        "issued_at": datetime.utcnow().isoformat(),
        "issuer": "JSEAL",
        "signature": base64.b64encode(f"signed-{req.certificate_id}".encode()).decode()[:50]
    }

    # Try permanent upload
    cid = upload_to_lighthouse(cert_data, req.certificate_id)

    # Save locally with permanent link
    stored = {
        **cert_data,
        "lighthouse_cid": cid,
        "lighthouse_gateway": f"https://gateway.lighthouse.storage/ipfs/{cid}" if cid else None,
        "permanent": cid is not None
    }
    certificates_db[req.certificate_id] = stored

    return {
        "certificate_id": req.certificate_id,
        "name": req.name,
        "arweave_tx_id": None,
        "lighthouse_cid": cid,
        "lighthouse_gateway": stored["lighthouse_gateway"],
        "permanent_url": stored["lighthouse_gateway"],
        "message": "Permanent" if cid else "Local only - Lighthouse failed but cert saved"
    }

@app.get("/api/v1/certificates/verify/{cert_id}")
def verify_certificate(cert_id: str):
    cert = certificates_db.get(cert_id)
    if not cert:
        return {"valid": False, "message": "Certificate not found"}
    return {"valid": True, "certificate": cert}

@app.get("/api/v1/trust-root")
def get_trust_root():
    return trust_root
