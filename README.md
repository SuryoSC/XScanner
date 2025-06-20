# XScanner

**XScanner** adalah alat scanner web otomatis berbasis Python untuk mendeteksi berbagai jenis kerentanan pada target website. Alat ini menggabungkan teknik crawling, fingerprinting, dan payload injection untuk membantu pentester dalam proses audit keamanan.

---

## 🚀 Fitur Unggulan

- ✅ SQL Injection Detection  
- ✅ Cross-site Scripting (XSS) Detection  
- ✅ Directory Traversal Detection  
- ✅ XML External Entity (XXE) Detection  
- ✅ Remote Code Execution (RCE) Detection  
- ✅ Local File Inclusion (LFI) Detection  
- ✅ Admin Panel Finder (termasuk CPanel Brute-force & WordPress User Enumeration)  
- ✅ Link Auto-Crawling menggunakan Selenium (Undetected ChromeDriver) dan fallback Requests-HTML  
- ✅ Informasi domain: status hidup/mati, dan usia domain via WHOIS  
- ✅ Log hasil dalam file `result/`  
- ✅ Output berwarna (termcolor, colorama, rich)

---

## 🖼️ Contoh Hasil Scan

> Output ditampilkan secara berwarna di terminal dan disimpan otomatis dalam file `.txt`.

![XScanner Terminal Output](/screenshot/xscanner-output.png)

---

## 📦 Instalasi

### 1. Kloning repositori:
```bash
git clone https://github.com/SuryoSC/XScanner
cd XScanner
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```

Jika tidak dapat menginstall `requirements.txt`, install manual:
```bash
pip install requests beautifulsoup4 termcolor colorama rich pyfiglet selenium undetected-chromedriver requests-html python-whois
```

---

## ⚙️ Persiapan

- Anda bisa mengedit file `users.txt` dan `password.txt` jika ingin menggunakan wordlist anda sendiri.
- Pastikan `Chrome` terinstall agar Selenium bekerja optimal.
- Untuk hasil optimal crawling, jalankan dengan headless opsional:
```bash
python main.py --headless
```

---

## 🔍 Cara Menggunakan

```bash
python main.py
```

Lalu masukkan URL target (wajib pakai `http://` atau `https://`), contoh:

```
Masukkan URL target: http://example.com
```

---

## 📁 Struktur Direktori

```
XScanner/
├── main.py
├── result/
│   └── example_com.txt     # hasil scan tersimpan di sini
├── screenshots/
│   └── xscanner-output.png # contoh screenshot output
├── users.txt               # daftar username untuk brute-force CPanel
├── password.txt            # daftar password untuk brute-force CPanel
└── README.md
```

---

## 🛡️ Catatan

- Tool ini hanya untuk **penetration testing legal**, gunakan **hanya pada sistem yang Anda miliki izin untuk diuji**.
- Penggunaan untuk kegiatan ilegal adalah **sepenuhnya tanggung jawab pengguna**.

---

## 🙏 Kredit

- Dibangun dengan ❤️ oleh SuryoSC
- library used:
  - `requests`, `beautifulsoup4`, `selenium`, `undetected-chromedriver`, `requests-html`, `whois`, `pyfiglet`, `rich`, dll.

---

## 📜 Lisensi

Proyek ini bersifat open-source dan bebas digunakan untuk keperluan edukasi atau profesional yang sah.

