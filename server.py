import os, json, uuid, hashlib, requests
from datetime import datetime, timezone
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nacl.signing, nacl.encoding

app = FastAPI(title="JSeal Permanent Free")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DB_PATH = os.getenv("JSEAL_DB_PATH","certificates_db.json")
def _load_db():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH,"r") as f: return json.load(f)
        except: return {}
    return {}
def _save_db():
    try:
        with open(DB_PATH,"w") as f: json.dump(certificates_db,f,indent=2)
    except: pass
certificates_db=_load_db()

# --- LOCK YOUR KEY ---
_signing_key=None
def _load_key():
    global _signing_key
    env=os.getenv("JSEAL_SIGNING_KEY")
    if env:
        try:
            _signing_key=nacl.signing.SigningKey(bytes.fromhex(env.strip()[:64]))
            print("[JSeal] Key from JSEAL_SIGNING_KEY env")
            return
        except: pass
    if os.path.exists("signing_key.hex"):
        try:
            with open("signing_key.hex","r") as f:
                _signing_key=nacl.signing.SigningKey(bytes.fromhex(f.read().strip()[:64]))
            print("[JSeal] Key from file")
            return
        except: pass
    _signing_key=nacl.signing.SigningKey.generate()
    try:
        with open("signing_key.hex","w") as f: f.write(_signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
    except: pass
    priv=_signing_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    pub=_signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    print(f"*** NEW KEY - SAVE TO RENDER ENV JSEAL_SIGNING_KEY={priv} *** PUB={pub}")

_load_key()
def get_pub(): return _signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
def canon(p): return json.dumps(p,sort_keys=True,separators=(",",":"))
def sign_payload(payload):
    msg=canon(payload).encode()
    return hashlib.sha256(msg).hexdigest(), _signing_key.sign(msg).signature.hex()

# --- PERMANENT FREE STORAGE - NO PAYMENT ---
# You just need free Pinata JWT: pinata.cloud -> Sign up free -> API Keys -> New Key -> Copy JWT
PINATA_JWT=os.getenv("PINATA_JWT","") # Free 1GB forever

def upload_permanent(bundle: dict, cert_id: str) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (ipfs_cid, permanent_url) - free forever, no $12/mo
    """
    data=json.dumps(bundle).encode()

    # 1) Pinata free (1GB free forever)
    if PINATA_JWT:
        try:
            r=requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS",
                headers={"Authorization": f"Bearer {PINATA_JWT}"},
                files={"file": (f"{cert_id}.json", data, "application/json")},
                data={"pinataMetadata": json.dumps({"name": f"{cert_id}.json"})},
                timeout=30)
            print(f"[Pinata] {r.status_code}")
            if r.status_code in (200,201):
                cid=r.json().get("IpfsHash")
                url=f"https://gateway.pinata.cloud/ipfs/{cid}"
                print(f"[Pinata] SUCCESS {cert_id} -> {url}")
                return cid, url
            else:
                print(f"[Pinata] failed: {r.text[:400]}")
        except Exception as e:
            print(f"[Pinata] error: {e}")

    # 2) Fallback: public IPFS (works without key, but slower)
    try:
        # Try nft.storage free endpoint (storacha)
        r=requests.post("https://api.web3.storage/upload",
            headers={"Content-Type":"application/json"},
            data=data, timeout=30)
        if r.status_code in (200,201):
            cid=r.json().get("cid")
            if cid:
                print(f"[web3.storage] SUCCESS {cert_id} -> https://w3s.link/ipfs/{cid}")
                return cid, f"https://w3s.link/ipfs/{cid}"
    except: pass

    print(f"[{cert_id}] No PINATA_JWT set, saved locally only. Set PINATA_JWT env to get permanent IPFS link.")
    return None, None

def build_bundle(cid,payload,dh,sig): return {"jseal_version":"1.0","certificate_id":cid,"payload":payload,"hash":{"algorithm":"SHA-256","digest_hex":dh},"signature":{"algorithm":"Ed25519","signature_hex":sig}}

def _issue(cert_id,event_id,recipient):
    issued=datetime.now(timezone.utc).isoformat()
    payload={"cert_id":cert_id,"event_id":event_id,"issued_at":issued,"recipient_name":recipient}
    dh,sig=sign_payload(payload)
    bundle=build_bundle(cert_id,payload,dh,sig)
    ipfs_cid, perm_url = upload_permanent(bundle,cert_id)
    certificates_db[cert_id]={"cert_id":cert_id,"event_id":event_id,"recipient_name":recipient,"issued_at":issued,"status":"ACTIVE","data_hash":dh,"signature":sig,"ipfs_cid":ipfs_cid,"permanent_url":perm_url,"bundle":bundle}
    _save_db()
    return payload,dh,sig,ipfs_cid,perm_url

class IssueRequest(BaseModel): cert_id:str; event_id:str; recipient_name:str; force:bool=False
class BatchRecord(BaseModel): recipient_name:str; cert_id:Optional[str]=None
class BatchIssueRequest(BaseModel): event_id:str; cert_prefix:str="cert"; records:List[BatchRecord]; force:bool=False

@app.get("/")
def root(): return {"status":"JSeal free permanent live","public_key":get_pub(),"total":len(certificates_db)}
@app.get("/health")
def health(): return {"status":"ok","public_key":get_pub(),"total":len(certificates_db),"pinata_configured": bool(PINATA_JWT)}
@app.get("/api/v1/trust-root")
def trust(): return {"issuer":"JSEAL","algorithm":"Ed25519","public_key_hex":get_pub()}
@app.post("/api/v1/certificates/issue")
def issue(req:IssueRequest):
    if certificates_db.get(req.cert_id) and not req.force: raise HTTPException(409,"exists")
    p,dh,sig,cid,url=_issue(req.cert_id,req.event_id,req.recipient_name)
    return {"cert_id":req.cert_id,"payload":p,"data_hash":dh,"signature":sig,"ipfs_cid":cid,"permanent_url":url}
@app.get("/api/v1/certificates/verify/{cert_id}")
def verify(cert_id:str):
    r=certificates_db.get(cert_id)
    if not r: return {"found":False}
    return {"found":True,**r}
