# File utama API yang menjadi core logic dari layanan keamanan (security service)
# Peran server dijelaskan pada soal
# TIPS: Gunakan file .txt sederhana untuk menyimpan data-data pengguna

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import os
from datetime import datetime
from contextlib import contextmanager

app = FastAPI(title="Security Service", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        with open("...", "...") as f:
            # Lanjutkan dengan logika pemrograman yang dibutuhkan di sini
            #
            #
    except Exception as e:
        return {
            "message": e
        }
    
    return {
        "message": "File uploaded!",
        "content-type": ctype
    }
    
# Fungsi API untuk menerima public key dan memastikan keutuhan file public key yang diterima
# TODO:
# Lengkapi fungsi berikut untuk menerima unggahan, memeriksa keutuhan file, lalu
# menyimpan public key milik user siapa
# Tentukan parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/store")
async def store_pubkey(...):
    # pesan kembalian ke user (sukses/gagal)
    msg = None

    # Tuliskan code Anda di sini
    #
    #
    #
    
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        ...
    }
    
# Fungsi API untuk memverifikasi signature yang dibuat oleh seorang pengguna
# TODO:
# Lengkapi fungsi berikut untuk menerima signature, menghitung signature dari "tampered message"
# Lalu kembalikan hasil perhitungan signature ke requester
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/verify")
async def verify(...):
    # pesan kembalian ke user (sukses/gagal)
    msg = None

    # Tuliskan code Anda di sini
    #
    #
    #
    
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        ...
    }

# Fungsi API untuk relay pesan ke user lain yang terdaftar
# TODO:
# Lengkapi fungsi berikut untuk menerima pesan yang aman ke server, 
# untuk selanjutnya diteruskan ke penerima yang dituju (ditentukan oleh pengirim)
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/relay")
async def relay(...):
    # pesan kembalian ke user (sukses/gagal)
    msg = None

    # Tuliskan code Anda di sini
    #
    #
    #
    
    # Nilai kembalian berupa dictionary
    # Tambahkan keys dan values sesuai dengan kebutuhan
    return {
        "message": msg,
        ...
    }