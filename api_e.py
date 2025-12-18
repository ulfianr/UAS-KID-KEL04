# API SKOR E
# File utama API yang menjadi core logic dari layanan keamanan (security service)
# Peran server dijelaskan pada soal
# TIPS: Gunakan file .txt sederhana untuk menyimpan data-data pengguna

from urllib import request
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from pydantic import BaseModel
import os
from datetime import datetime
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

app = FastAPI(title="Security Service", version="1.0.0")
# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("punkhazard-keys/priv.pem", "rb") as f:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )

def derive_shared_key(priv, peer_pub):
    secret = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-ecdh",
        backend=default_backend(),
    ).derive(secret)

# Fungsi contoh untuk memeriksa apakah layanan berjalan dengan baik (health check)
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# Fungsi akses pada lokasi "root" atau "index"
@app.get("/")
async def get_index() -> dict:
	return {
		"message": "Hello world! Please visit http://localhost:8080/docs for API UI."
	}

# Fungsi contoh untuk mengunggah file pdf
# Akses API pada URL http://localhost:8080/upload-pdf
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    fname = file.filename
    ctype = file.content_type

    try:
        contents = await file.read()
        os.makedirs("uploads", exist_ok=True)
        with open(f"uploads/{fname}", "wb") as f:
            f.write(contents)
            # Lanjutkan dengan logika pemrograman yang dibutuhkan di sini
    except Exception as e:
        # Handle the exception and provide a meaningful response
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
        return {
            "message": str(e)
        }

    return {
        "message": "File uploaded!",
        "content-type": ctype,
        "filename": fname
    }
# Fungsi API untuk menerima public key dan memastikan keutuhan file public key yang diterima
# TODO:
# Lengkapi fungsi berikut untuk menerima unggahan, memeriksa keutuhan file, lalu
# menyimpan public key milik user siapa
# Tentukan parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/store")
async def store_pubkey(
    username: str,
    pubkey: UploadFile = File(...)
):
    # pesan kembalian ke user (sukses/gagal)
    msg = None
    # Tuliskan code Anda di sini
    try:
        data = await pubkey.read()

        if b"PUBLIC KEY" not in data:
            raise HTTPException(status_code=400, detail="Invalid public key format")

        os.makedirs("pubkeys", exist_ok=True)
        with open(f"pubkeys/{username}.pem", "wb") as f:
            f.write(data)

        msg = "Public key stored successfully"

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        "user": username
    }
# Fungsi API untuk memverifikasi signature yang dibuat oleh seorang pengguna
# TODO:
# Lengkapi fungsi berikut untuk menerima signature, menghitung signature dari "tampered message"
# Lalu kembalikan hasil perhitungan signature ke requester
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/verify")
async def verify(
    username: str,
    message: str,
    signature: str,
    algo: str
):
    # pesan kembalian ke user (sukses/gagal)
    msg = None
    valid = False
    # Tuliskan code Anda di sini
    try:
        with open(f"pubkeys/{username}.pem", "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())

        sig_bytes = base64.b64decode(signature)

        if algo == "ecdsa":
            pubkey.verify(
                sig_bytes,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
        elif algo == "ed25519":
            pubkey.verify(
                sig_bytes,
                message.encode()
            )
        else:
            raise HTTPException(status_code=400, detail="Unknown algorithm")

        msg = "Signature VALID"
        valid = True

    except Exception:
        msg = "Signature INVALID"
        valid = False
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        "user": username,
        "valid": valid
    }

# Fungsi API untuk relay pesan ke user lain yang terdaftar
# TODO:
# Lengkapi fungsi berikut untuk menerima pesan yang aman ke server, 
# untuk selanjutnya diteruskan ke penerima yang dituju (ditentukan oleh pengirim)
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini  
@app.post("/relay")
async def relay(
    sender: str,
    receiver: str,
    certificate: str,
    client_public_key: str,
    ephemeral_public_key: str,
    nonce: str,
    ciphertext: str,
    signature_ed25519: str,
    signature_ecdsa: str
):
    msg = None
    success = False
    try:
        # Dekode data Base64
        eph_pub_bytes = base64.b64decode(ephemeral_public_key)
        eph_pub = serialization.load_pem_public_key(eph_pub_bytes)
        nonce_b = base64.b64decode(nonce)
        cipher_b = base64.b64decode(ciphertext)
        # Proses Derivasi Kunci & Dekripsi (Logika Inti)
        shared_key = derive_shared_key(SERVER_PRIVATE_KEY, eph_pub)
        aesgcm = AESGCM(shared_key)
        aad = f"{sender}|{receiver}".encode()
        plaintext = aesgcm.decrypt(nonce_b, cipher_b, aad)
        # Simpan pesan ke file
        os.makedirs("messages", exist_ok=True)
        with open(f"messages/{receiver}.txt", "a") as f:
            f.write(f"From {sender}: {plaintext.decode()}\n")

        msg = "Secure message relayed successfully"
        success = True

    except Exception as e:
        msg = f"Relay failed: {str(e)}"
        success = False
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        "from": sender,
        "to": receiver,
        "success": success
    }