# Reverse Engineering Kopi Kenangan — Security Research

Analisis keamanan (reverse engineering) aplikasi Android **Kopi Kenangan** (`com.kopikenangan`,
Flutter/Dart 3.12.2 AOT) — fokus pada mekanisme penandatanganan request (`clsignature`),
enkripsi body, dan anti-bot `wToken` (Alibaba TigerTally).

> ## ⚠️ PERINGATAN ETIS
> Repositori ini dibuat **hanya untuk tujuan edukasi dan riset keamanan (bug bounty internal)**.
> - **Jangan** gunakan temuan/script ini untuk mengakses server Kopi Kenangan tanpa izin
>   (bot, akun massal, promo abuse, scraping = pelanggaran ToS & berisiko hukum).
> - **Tidak ada request ke server produksi** yang dikirim selama riset; semua verifikasi
>   dilakukan terhadap data capture pribadi (HAR) milik peneliti.
> - `wToken` (TigerTally) tetap menjadi penghalang sah yang **tidak bisa dipalsukan**
>   tanpa device nyata — lihat `docs/WTOKEN_RESEARCH_REPORT.md`.
> - Disarankan melakukan **responsible disclosure** ke tim keamanan Kopi Kenangan
>   sebelum publikasi lebih lanjut.

---

## Ringkasan Temuan Utama

| Komponen | Algoritma | Status |
|---|---|---|
| **`clsignature`** | `HMAC-SHA256(SECRET, plaintext_body)` | ✅ Terverifikasi 22+ request HAR |
| **Enkripsi body** (endpoint protected) | `AES-256-CBC`, PKCS7, format `base64(rnd(3)+0x01+ct)` | ✅ Terverifikasi (register/login terdekripsi) |
| **Response body** | Plaintext JSON (tidak dienkripsi) | ✅ |
| **`wToken`** | Alibaba TigerTally (`libtiger_tally.so`), versi `0004` | ❌ Tidak bisa dipalsukan — fingerprint dari server Alibaba |

**Secret tunggal** (hardcoded di `libapp.so`, object pool `[pp+0xc6f8]`):
```
suomafsehwonhtuoyylraeniemohtfel
```
- Kunci HMAC `clsignature` **dan** kunci AES-256 **dan** IV-nya (`secret[:16]`).
- Temuan keamanan: satu secret di-hardcode di client → CWE-798 (Use of Hard-coded Credentials).

Detail lengkap: [`docs/FINAL_REPORT.md`](docs/FINAL_REPORT.md)

---

## Struktur Repositori

```
├── README.md                        # File ini
├── docs/                            # Semua laporan analisis
│   ├── REPORT.md                    # Laporan statis awal (APK, blutter, TigerTally)
│   ├── FINAL_REPORT.md              # Laporan dekripsi kriptografi (clsignature + AES)
│   ├── FLOW_REPORT.md               # Alur bisnis register→OTP→login→promo
│   ├── REQUEST_MATCH_TEST.md        # Bukti kecocokan script vs HAR
│   ├── WT_TOKEN_ANALYSIS.md         # Analisa wToken & libtiger_tally.so
│   ├── WTOKEN_DEEP_ANALYSIS.md      # Analisa kelayakan pembuatan wToken
│   ├── WTOKEN_RESEARCH_REPORT.md    # Riset lintas platform (7+ sumber)
│   ├── WTOKEN_CHINA_DEEP_RESEARCH_AND_TEST.md  # Riset forum China (19 sumber) + uji
│   ├── NO_FRIDA_WTOKEN_GUIDE.md     # Ambil wToken via MITM proxy (tanpa Frida)
│   ├── REAL_TEST_GUIDE.md           # Panduan real test langkah demi langkah
│   ├── china_sources.md             # Daftar 19 sumber riset China
│   ├── python_test_results.md       # Hasil uji script Python
│   └── unidbg_test_results.md       # Hasil uji implementasi unidbg
├── scripts/
│   ├── kopken_flow.py               # Script utama: alur + menu interaktif + selftest
│   ├── kopken_request.py            # Fungsi kriptografi dasar + request builder
│   └── frida_get_wtoken.py          # Helper ambil wToken via Frida (opsional)
├── poc/
│   ├── poc_kopikenangan.py          # PoC awal (verifikasi rumus)
│   └── frida_kopikenangan.js        # Frida hook script (clsignature/AES/gsRaw)
├── evidence/
│   ├── kk_requests_sanitized.json   # 24 request API dari HAR (tanpa data pribadi)
│   └── refrensi_unidbg_chomper.txt  # Referensi kode unidbg/Chomper (dgn sumber)
└── HAR/
    └── README.md                    # Catatan: HAR asli dikecualikan (data pribadi)
```

**Catatan:** `libtiger_tally.so` (binary proprietary Alibaba) tidak disertakan karena
hak cipta — ekstrak sendiri dari APK resmi (`lib/arm64-v8a/`, versi app 126.08.13).

---

## Cara Menggunakan Script

### Prasyarat
```bash
pip install requests pycryptodome
```

### 1) Self-test (verifikasi rumus kriptografi — tanpa kirim request)
```bash
python3 scripts/kopken_flow.py --selftest
# => SEMUA PASS (HMAC + AES round-trip + dekripsi sampel)
```

### 2) Menu interaktif (mode default)
```bash
python3 scripts/kopken_flow.py
# 1=Register  2=Login(OTP)  3=CheckWelcome  4=Flow penuh
# 6=Dekripsi body  7=Selftest  10=Cek kesehatan wToken
# Mode default = SIMULASI (dry-run). Kirim nyata butuh konfirmasi eksplisit.
```

### 3) CLI
```bash
# Simulasi alur penuh (tidak kirim):
python3 scripts/kopken_flow.py --flow --dry-run --phone 00628XXXXXXXXX --otp 123456

# Kirim nyata (BUTUH wToken valid dari device nyata via MITM proxy):
python3 scripts/kopken_flow.py --step register --send \
    --phone 00628XXXXXXXXX --wtoken file:wtoken.txt \
    --deviceid <dari_proxy> --appsflyer-id <dari_proxy>
```

### 4) Ambil wToken (tidak bisa dibuat Python)
Lihat [`docs/NO_FRIDA_WTOKEN_GUIDE.md`](docs/NO_FRIDA_WTOKEN_GUIDE.md) —
MITM proxy (`mitmproxy`) + CA cert di device. wToken **wajib** dari device nyata;
emulator menghasilkan fingerprint kosong (`||`) → server menolak (HTTP 405).

---

## Metodologi Singkat

1. **Statis**: XAPK → APK split → `libapp.so` (Dart AOT) via **blutter** + capstone;
   `libtiger_tally.so` via readelf/strings/imports; jadx utk Java bridge.
2. **Dinamis (data capture)**: HAR (76 entri) → verifikasi rumus, struktur wToken,
   pasangan wToken↔deviceid.
3. **Uji**: self-test + dry-run vs HAR (clsignature & ciphertext MATCH),
   health-check wToken, percobaan unidbg (terdokumentasi di docs/).

## Kredit & Referensi

- Tool: [blutter](https://github.com/worawit/blutter), [jadx](https://github.com/skylot/jadx),
  [unidbg](https://github.com/zhkl0228/unidbg), [capstone](http://www.capstone-engine.org/)
- Referensi riset TigerTally: 19 sumber (CSDN, Tencent Cloud, cnblogs, Jianshu,
  kanxue, dll.) — daftar lengkap di [`docs/china_sources.md`](docs/china_sources.md)
- Riset dilakukan oleh pemilik repo pada device & akun milik sendiri.

## Lisensi
Konten analisis: MIT.
Logo/nama/apk Kopi Kenangan & SDK Alibaba adalah milik pemiliknya masing-masing.
