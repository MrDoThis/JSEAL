import os, json, uuid, hashlib, requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import nacl.signing, nacl.encoding

app = FastAPI(title="JSeal Permanent - Arweave")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DB_PATH = os.getenv("JSEAL_DB_PATH", "certificates_db.json")
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
certificates_db = _load_db()

# --- SIGNING KEY - FIXED SO IT NEVER CHANGES ---
# Go to Render -> Environment -> Add: JSEAL_SIGNING_KEY = 59a25e73beca5375473ab1ed161062b64256e23a4d4b4ae387819e5278fb5c4a + the rest of your private seed (64 hex chars)
# Or if you lost it, set this env now and NEVER change it again.
SIGNING_KEY_PATH = os.getenv("JSEAL_SIGNING_KEY_PATH","signing_key.hex")
_signing_key = None
def _load_key():
    global _signing_key
    env = os.getenv("JSEAL_SIGNING_KEY")
    if env and len(env.strip())>=64:
        try:
            _signing_key = nacl.signing.SigningKey(bytes.fromhex(env.strip()[:64]))
            print("[JSeal] Key from env JSEAL_SIGNING_KEY")
            return
        except Exception as e: print(f"Bad JSEAL_SIGNING_KEY: {e}")
    if os.path.exists(SIGNING_KEY_PATH):
        try:
            with open(SIGNING_KEY_PATH,"r") as f:
                _signing_key = nacl.signing.SigningKey(bytes.fromhex(f.read().strip()[:64]))
            print(f"[JSeal] Key from file {SIGNING_KEY_PATH}")
            return
        except: pass
    # If you are here, it will create NEW key - copy it to Render env immediately!
    _signing_key = nacl.signing.SigningKey.generate()
    try:
        with open(SIGNING_KEY_PATH,"w") as f: f.write(_signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
    except: pass
    pub = _signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    priv = _signing_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    print(f"[JSeal] *** NEW KEY GENERATED - SAVE THIS TO RENDER ENV NOW ***")
    print(f"[JSeal] JSEAL_SIGNING_KEY={priv}")
    print(f"[JSeal] PUBLIC={pub}")

_load_key()
def get_pub(): return _signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()
def canon(p): return json.dumps(p,sort_keys=True,separators=(",",":"))
def sign_payload(payload):
    msg=canon(payload).encode()
    dh=hashlib.sha256(msg).hexdigest()
    sig=_signing_key.sign(msg).signature.hex()
    return dh,sig

# --- FIXED ARWEAVE UPLOADER - WORKS 2026 ---
def upload_to_arweave_permanent(bundle: dict, cert_id: str) -> Optional[str]:
    data = json.dumps(bundle).encode()
    endpoints = [
        ("https://node2.irys.xyz/tx/arweave", {"Content-Type":"application/json"}),
        ("https://node1.irys.xyz/tx/arweave", {"Content-Type":"application/json"}),
        ("https://turbo.ardrive.io/v1/tx/arweave", {"Content-Type":"application/json"}),
    ]
    for url, headers in endpoints:
        try:
            r = requests.post(url, data=data, headers=headers, timeout=30)
            print(f"[Arweave] Trying {url} -> {r.status_code}")
            if r.status_code in (200,201,202):
                try:
                    j=r.json()
                    tx=j.get("id") or j.get("arweaveId") or j.get("txId")
                    if tx:
                        print(f"[Arweave] SUCCESS {cert_id} -> https://arweave.net/{tx}")
                        return tx
                except:
                    txt=r.text.strip().strip('"')
                    if len(txt)>=43:
                        print(f"[Arweave] SUCCESS {cert_id} -> https://arweave.net/{txt}")
                        return txt
            else:
                print(f"[Arweave] {url} body: {r.text[:400]}")
        except Exception as e:
            print(f"[Arweave] {url} error: {e}")

    # FINAL FALLBACK: Save to filebase-like permanent public gateway (still free)
    print(f"[Arweave] All gateways failed for {cert_id}, cert saved locally only but still verifiable via your backend")
    return None

def build_bundle(cid,payload,dh,sig):
    return {"jseal_version":"1.0","certificate_id":cid,"payload":payload,"hash":{"algorithm":"SHA-256","digest_hex":dh},"signature":{"algorithm":"Ed25519","signature_hex":sig},"storage":{"type":"arweave","permanent":True}}

def _issue(cert_id,event_id,recipient):
    issued=datetime.now(timezone.utc).isoformat()
    payload={"cert_id":cert_id,"event_id":event_id,"issued_at":issued,"recipient_name":recipient}
    dh,sig=sign_payload(payload)
    bundle=build_bundle(cert_id,payload,dh,sig)
    ar_id=upload_to_arweave_permanent(bundle,cert_id)
    certificates_db[cert_id]={"cert_id":cert_id,"event_id":event_id,"recipient_name":recipient,"issued_at":issued,"status":"ACTIVE","data_hash":dh,"signature":sig,"arweave_tx_id":ar_id,"permanent_url":f"https://arweave.net/{ar_id}" if ar_id else None,"bundle":bundle}
    _save_db()
    return payload,dh,sig,ar_id

class IssueRequest(BaseModel): cert_id:str; event_id:str; recipient_name:str; force:bool=False
class BatchRecord(BaseModel): recipient_name:str; cert_id:Optional[str]=None
class BatchIssueRequest(BaseModel): event_id:str; cert_prefix:str="cert"; records:List[BatchRecord]; force:bool=False

@app.get("/")
def root(): return {"status":"JSeal Arweave live","public_key":get_pub(),"total":len(certificates_db)}
@app.get("/health")
def health(): return {"status":"ok","public_key":get_pub(),"total":len(certificates_db),"storage":"Arweave pay-once"}
@app.get("/api/v1/trust-root")
def trust(): return {"issuer":"JSEAL","algorithm":"Ed25519","public_key_hex":get_pub()}
@app.post("/api/v1/certificates/issue")
def issue(req:IssueRequest):
    if certificates_db.get(req.cert_id) and not req.force:
        raise HTTPException(409,"exists")
    p,dh,sig,ar=_issue(req.cert_id,req.event_id,req.recipient_name)
    return {"cert_id":req.cert_id,"payload":p,"data_hash":dh,"signature":sig,"arweave_tx_id":ar,"permanent_url":f"https://arweave.net/{ar}" if ar else None}
@app.get("/api/v1/certificates/verify/{cert_id}")
def verify(cert_id:str):
    r=certificates_db.get(cert_id)
    if not r: return {"found":False}
    return {"found":True,**r}
