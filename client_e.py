
# CLIENT SKOR E
# # File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

import json
from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import datetime
import os
import base64

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

SENDER_ID = "client-ayam-kremes"
RECEIVER_ID = "server-punkhazard"

# TODO: Lengkapi proses-proses pembuatan private dan public key
# untuk users yang disimulasikan
#SECP256K1
priv_client_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
pub_client_key = priv_client_key.public_key()
#ED25519
priv1 = ed25519.Ed25519PrivateKey.generate()
pub1 = priv1.public_key()
# Simpan ke file SECP256K1
with open("priv_client.pem", "wb") as f:
    f.write(priv_client_key.private_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption()))
with open("pub_client.pem", "wb") as f:
    f.write(pub_client_key.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
# Simpan ke file ED25519
with open("priv1.pem", "wb") as f:
    f.write(priv1.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()))
with open("pub1.pem", "wb") as f:
    f.write(pub1.public_bytes(encoding=serialization.Encoding.PEM,
                              format=serialization.PublicFormat.SubjectPublicKeyInfo))

# TODO: Lengkapi proses-proses lain enkripsi simetrik (jika dibutuhkan)
# di mana pesan rahasia tersebut akan ditransmisikan
#
# Tulis code Anda di bawah ini
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
                              x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jawa Timur"),
                              x509.NameAttribute(NameOID.LOCALITY_NAME, "Surabaya"),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ayam Kremes"),
                              x509.NameAttribute(NameOID.COMMON_NAME, SENDER_ID)])
cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(pub_client_key).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(priv_client_key, hashes.SHA256(), default_backend()))
with open("client_certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# Pesan rahasia yang ingin dikirim ke server
message = b"Diam - diam yaa ini pesan rahasia."
signature_ed25519 = priv1.sign(message)
signature_ecdsa = priv_client_key.sign(message, ec.ECDSA(hashes.SHA256()))
print("Signature ED25519:", len(signature_ed25519))
print("Signature ECDSA:", len(signature_ecdsa))

def derive_shared_key(priv_ec, peer_pub):
    secret = priv_ec.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, 
                info=b"ecdh-ecies", backend=default_backend()).derive(secret)

def encrypt_ecies(recipient_pub, plaintext, sender_id, receiver_id):
    eph_priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    eph_pub = eph_priv.public_key()
    key = derive_shared_key(eph_priv, recipient_pub)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"{sender_id}|{receiver_id}".encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    eph_pub_pem = eph_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return eph_pub_pem, nonce, ciphertext

with open("punkhazard-keys/pub.pem", "rb") as f:
    server_public_key = serialization.load_pem_public_key(f.read())

eph_pub_pem, nonce, ciphertext = encrypt_ecies(
    server_public_key,
    message,
    SENDER_ID,
    RECEIVER_ID,
)

with open("pub_client.pem", "rb") as f:
    client_pub_pem = f.read()

with open("client_certificate.pem", "rb") as f:
    cert_pem = f.read()

payload = {
    "sender": SENDER_ID,
    "receiver": RECEIVER_ID,
    "certificate": b64(cert_pem),
    "client_public_key": b64(client_pub_pem),
    "ephemeral_public_key": b64(eph_pub_pem),
    "nonce": b64(nonce),
    "ciphertext": b64(ciphertext),
    "signature_ed25519": b64(signature_ed25519),
    "signature_ecdsa": b64(signature_ecdsa),
}

print("Payload siap dikirim ke server:")
payload_json = json.dumps(payload, indent=4)
print(payload_json)