# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# TODO: Lengkapi proses-proses pembuatan private dan public key
# untuk users yang disimulasikan
priv_key = ...
pub_key = ...

# TODO: Lengkapi proses-proses lain enkripsi simetrik (jika dibutuhkan)
# di mana pesan rahasia tersebut akan ditransmisikan
#
# Tulis code Anda di bawah ini
#
#