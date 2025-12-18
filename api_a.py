##Skor A API
# File utama API - Security Service
import hashlib
from fastapi import FastAPI, HTTPException, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

app = FastAPI(title="Security Service", version="1.0.0")
AUTHORIZED_USERS = ["client-ayam-kremes", "server-punkhazard"]

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load server private key
with open("punkhazard-keys/priv.pem", "rb") as f:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Simulasi token user
USER_TOKENS = {
    "client-ayam-kremes": "token123456789",
    "server-punkhazard": "token987654321"
}

# Helper functions
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode())

def derive_shared_key(priv, peer_pub):
    secret = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-ecdh",
        backend=default_backend()
    ).derive(secret)

def verify_token(username: str, authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Missing or invalid Bearer token")
    token = authorization.split()[1]
    expected = USER_TOKENS.get(username)
    if token != expected:
        raise HTTPException(status_code=403, detail="Unauthorized token")

# Health check
@app.get("/health")
async def health_check():
    return {"status": "Security Service is running", "timestamp": datetime.now().isoformat()}

# Index
@app.get("/")
async def get_index():
    return {"message": "Hello world! Visit http://localhost:8080/docs for API UI."}

# Upload PDF
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    os.makedirs("uploads", exist_ok=True)
    try:
        contents = await file.read()
        with open(f"uploads/{file.filename}", "wb") as f:
            f.write(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Upload failed: {str(e)}")
    return {"message": "File uploaded!", "filename": file.filename, "content-type": file.content_type}

# Store public key
@app.post("/store")
async def store_pubkey(username: str, algo: str, expected_hash: str,
                       pubkey: UploadFile = File(...), authorization: str = Header(None)):
    verify_token(username, authorization)

    if username not in AUTHORIZED_USERS:
        raise HTTPException(status_code=403, detail=f"User '{username}' tidak terdaftar.")
    try:
        data = await pubkey.read()
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            return {"message": "Integrity Check Gagal! File rusak atau dimodifikasi.", "success": False}

        user_dir = f"pubkeys/{username}"
        os.makedirs(user_dir, exist_ok=True)
        fname = "pub.pem" if algo.lower() == "ecdsa" else "pub19.pem"
        with open(f"{user_dir}/{fname}", "wb") as f:
            f.write(data)

        return {"message": "Public key stored successfully.", "user": username, "success": True, "hash_calculated": actual_hash}
    except Exception as e:
        return {"message": f"Error: {str(e)}", "user": username, "success": False}

# Verify message signature
@app.post("/verify")
async def verify(username: str, message: str, signature: str, algo: str, message_hash: str,
                 authorization: str = Header(None)):
    verify_token(username, authorization)

    if username not in AUTHORIZED_USERS:
        raise HTTPException(status_code=403, detail=f"User '{username}' tidak memiliki izin akses.")

    calculated_hash = hashlib.sha256(message.encode()).hexdigest()
    if calculated_hash != message_hash:
        return {"message": "Integrity Check Gagal! Pesan telah dimodifikasi.",
                "user": username, "valid": False, "integrity_check": "Failed",
                "calculated_hash": calculated_hash}

    valid = False
    msg = None
    try:
        key_file = f"pubkeys/{username}/pub.pem" if algo.lower() == "ecdsa" else f"pubkeys/{username}/pub19.pem"
        with open(key_file, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())
        sig_bytes = b64decode(signature)

        if algo.lower() == "ecdsa":
            pubkey.verify(sig_bytes, message.encode(), ec.ECDSA(hashes.SHA256()))
        elif algo.lower() == "ed25519":
            pubkey.verify(sig_bytes, message.encode())
        else:
            return {"message": "Unknown algorithm", "user": username, "valid": False}

        msg = "Signature VALID"
        valid = True
    except Exception:
        msg = "Signature INVALID"
        valid = False

    return {"message": msg, "user": username, "valid": valid, "algo": algo.lower(),
            "integrity_check": "Success" if valid else "Failed", "calculated_hash": calculated_hash}

# Verify PDF signature
@app.post("/verify-pdf")
async def verify_pdf(username: str, algo: str, pdf_hash: str, signature_pdf: str,
                     authorization: str = Header(None)):
    verify_token(username, authorization)

    key_file = f"pubkeys/{username}/pub.pem" if algo=="ecdsa" else f"pubkeys/{username}/pub19.pem"
    with open(key_file, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    
    sig_bytes = b64decode(signature_pdf)
    pdf_bytes = b64decode(pdf_hash)

    try:
        if algo == "ecdsa":
            pubkey.verify(sig_bytes, pdf_bytes, ec.ECDSA(hashes.SHA256()))
        elif algo == "ed25519":
            pubkey.verify(sig_bytes, pdf_bytes)
        else:
            return {"message": "Unknown algorithm", "valid": False}

        msg = "Signature VALID"
        valid = True
        return {"message": msg, "user": username,"valid": valid,
                "integrity_check": "Success" if valid else "Failed",
                "algo": algo, "calculated_hash": hashlib.sha256(pdf_bytes).hexdigest()}
    except:
        return {"message": msg, "user": username,"valid": False,
                "integrity_check": "Failed", "algo": algo,
                "calculated_hash": hashlib.sha256(pdf_bytes).hexdigest()}

# Relay secure message
@app.post("/relay")
async def relay(sender: str, receiver: str, ephemeral_public_key: str, nonce: str, ciphertext: str,
                signature: str = None, algo: str = None, ciphertext_hash: str = None,
                authorization: str = Header(None)):
    verify_token(sender, authorization)

    if sender not in AUTHORIZED_USERS or receiver not in AUTHORIZED_USERS:
        raise HTTPException(status_code=403, detail="Sender atau Receiver tidak terdaftar.")

    if ciphertext_hash and hashlib.sha256(ciphertext.encode()).hexdigest() != ciphertext_hash:
        return {"message": "Integrity Check Gagal! Ciphertext rusak.", "success": False}

    try:
        eph_pub = serialization.load_pem_public_key(b64decode(ephemeral_public_key))
        nonce_b = b64decode(nonce)
        cipher_b = b64decode(ciphertext)

        key = derive_shared_key(SERVER_PRIVATE_KEY, eph_pub)
        aesgcm = AESGCM(key)
        aad = f"{sender}|{receiver}".encode()
        plaintext = aesgcm.decrypt(nonce_b, cipher_b, aad)

        if signature:
            key_file = f"pubkeys/{sender}/pub.pem" if algo.lower()=="ecdsa" else f"pubkeys/{sender}/pub19.pem"
            with open(key_file, "rb") as f:
                pubkey = serialization.load_pem_public_key(f.read())
            sig_bytes = b64decode(signature)
            if algo.lower() == "ecdsa":
                pubkey.verify(sig_bytes, plaintext, ec.ECDSA(hashes.SHA256()))
            else:
                pubkey.verify(sig_bytes, plaintext)

        os.makedirs("messages", exist_ok=True)
        with open(f"messages/{receiver}.txt", "a") as f:
            f.write(f"From {sender}: {plaintext.decode()}\n")

        return {"message": "Secure message relayed", "from": sender, "to": receiver, "success": True}
    except Exception as e:
        return {"message": f"Relay failed: {str(e)}", "success": False}