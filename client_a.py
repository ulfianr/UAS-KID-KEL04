##Skor A Client
import json, os, base64, hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import datetime
from datetime import timezone
from cryptography import x509
from cryptography.x509.oid import NameOID

SERVER_URL = "http://localhost:8080"
SENDER_ID = "client-ayam-kremes"
RECEIVER_ID = "server-punkhazard"
SIGNATURE_ALGO = "ecdsa"
BEARER_TOKEN = "token123456789"  # sesuai api.py

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode())

# --- GENERATE KEY ---
priv_ec = ec.generate_private_key(ec.SECP256K1(), default_backend())
pub_ec = priv_ec.public_key()
priv_ed = ed25519.Ed25519PrivateKey.generate()
pub_ed = priv_ed.public_key()

# --- SIMPAN PEM ---
os.makedirs("keys", exist_ok=True)
with open("priv_client.pem", "wb") as f: f.write(priv_ec.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
with open("pub_client.pem", "wb") as f: f.write(pub_ec.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
with open("priv1.pem", "wb") as f: f.write(priv_ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
with open("pub1.pem", "wb") as f: f.write(pub_ed.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

# --- CERTIFICATE ---
# --- CERTIFICATE ---
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jawa Timur"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Surabaya"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ayam Kremes"),
    x509.NameAttribute(NameOID.COMMON_NAME, SENDER_ID)
])

# Gunakan datetime.now(timezone.utc) untuk menggantikan utcnow()
now = datetime.datetime.now(timezone.utc)

cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
    .public_key(pub_ec).serial_number(x509.random_serial_number())\
    .not_valid_before(now)\
    .not_valid_after(now + datetime.timedelta(days=365))\
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
    .sign(priv_ec, hashes.SHA256(), default_backend())

# subject = issuer = x509.Name([
#     x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jawa Timur"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, "Surabaya"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ayam Kremes"),
#     x509.NameAttribute(NameOID.COMMON_NAME, SENDER_ID)
# ])
# cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
#     .public_key(pub_ec).serial_number(x509.random_serial_number())\
#     .not_valid_before(datetime.datetime.utcnow())\
#     .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
#     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
#     .sign(priv_ec, hashes.SHA256(), default_backend())

# --- HASH PUBKEY ---
pub_ec_bytes = pub_ec.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
pub_ed_bytes = pub_ed.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
pub_ec_hash = hashlib.sha256(pub_ec_bytes).hexdigest()
pub_ed_hash = hashlib.sha256(pub_ed_bytes).hexdigest()

# --- MESSAGE & SIGNATURE ---
message = b"Diam - diam yaa ini pesan rahasia."
sig_ec = priv_ec.sign(message, ec.ECDSA(hashes.SHA256()))
sig_ed = priv_ed.sign(message)
message_hash = hashlib.sha256(message).hexdigest()

# --- PDF SIGNATURE ---
pdf_file = "uploads/Soal-UAS-KID25.pdf"
with open(pdf_file, "rb") as f: pdf_bytes = f.read()
pdf_hash = hashlib.sha256(pdf_bytes).digest()
sig_pdf_ec = priv_ec.sign(pdf_hash, ec.ECDSA(hashes.SHA256()))
sig_pdf_ed = priv_ed.sign(pdf_hash)

# --- ECIES ENCRYPTION ---
def derive_shared_key(priv_ec, peer_pub):
    secret = priv_ec.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh-ecies", backend=default_backend()).derive(secret)

def encrypt_ecies(pub_recipient, plaintext):
    eph = ec.generate_private_key(ec.SECP256K1(), default_backend())
    eph_pub = eph.public_key()
    key = derive_shared_key(eph, pub_recipient)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"{SENDER_ID}|{RECEIVER_ID}".encode()
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return eph_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), nonce, ct

# Load server public key
with open("punkhazard-keys/pub.pem", "rb") as f: server_pub = serialization.load_pem_public_key(f.read())
eph_pub_pem, nonce, ciphertext = encrypt_ecies(server_pub, message)

payload = {
    "username": SENDER_ID,
    "algo": SIGNATURE_ALGO,
    "store_expected_hash_ec": pub_ec_hash,
    "store_expected_hash_ed": pub_ed_hash,
    "verify_message_hash_ec": message_hash,
    "verify_message_hash_ed": message_hash,
    "signature_ecdsa": b64(sig_ec),
    "signature_ed25519": b64(sig_ed),
    "signature_pdf_ec": b64(sig_pdf_ec),
    "signature_pdf_ed": b64(sig_pdf_ed),
    "pdf_hash_ec": b64(pdf_hash),
    "pdf_hash_ed": b64(pdf_hash),
    "ciphertext": b64(ciphertext),
    "ciphertext_hash": hashlib.sha256(b64(ciphertext).encode()).hexdigest(),
    "ephemeral_public_key": b64(eph_pub_pem),
    "nonce": b64(nonce),
    "client_public_key_ec": b64(pub_ec_bytes),
    "client_public_key_ed": b64(pub_ed_bytes),
    "certificate": b64(cert.public_bytes(serialization.Encoding.PEM))
}

headers = {"Authorization": f"Bearer {BEARER_TOKEN}"}

# --- SEND TO STORE / VERIFY / RELAY / VERIFY-PDF ---
# Contoh: kirim public key ke /store
r = requests.post(f"{SERVER_URL}/store", headers=headers, files={"pubkey": ("pub.pem", pub_ec_bytes)}, data={"username": SENDER_ID, "algo": "ecdsa", "expected_hash": pub_ec_hash})
print("Store:", r.json())

# Contoh: verify message
r2 = requests.post(f"{SERVER_URL}/verify", headers=headers, data={
    "username": SENDER_ID,
    "message": message.decode(),
    "signature": b64(sig_ec),
    "algo": "ecdsa",
    "message_hash": message_hash
})
print("Verify:", r2.json())