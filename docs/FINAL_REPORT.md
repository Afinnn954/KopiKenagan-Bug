# LAPORAN AKHIR — Reverse Engineering Kopi Kenangan (SELESAI)

**Target:** `com.kopikenangan` (Flutter / Dart 3.12.2 AOT)
**Sumber data:** APK v126.08.13 (statis) + HAR v126.07.23/375 (dinamis, 76 entri)
**Hasil:** ✅ Formula `clsignature`, ✅ Kunci AES, ✅ Script request — **semua 100% terverifikasi terhadap data asli.**

> ⚠️ **Etika:** Laporan ini untuk riset keamanan/edukasi. Jangan mengakses server Kopi Kenangan tanpa izin.

---

## 1. Ringkasan Eksekutif

| Komponen | Algoritma | Status |
|---|---|---|
| **`clsignature`** | `HMAC-SHA256( SECRET , plaintext_body )` | ✅ TERVERIFIKASI (22/24 request HAR cocok; sisanya body-terenkripsi yg plaintext-nya sudah didekripsi & cocok) |
| **Body (protected endpoint)** | `AES-256-CBC`, PKCS7, format `[rnd(3)][0x01][ct]` lalu base64 | ✅ TERVERIFIKASI (register/login/thirdparty terdekripsi jadi JSON valid) |
| **Body (endpoint biasa)** | plaintext JSON (tidak dienkripsi) | ✅ |
| **Response body** | plaintext JSON (tidak dienkripsi) | ✅ |
| **`wtoken`** | Alibaba TigerTally (native `gsRaw`) | ⛔ tidak bisa dibuat Python → input eksternal dari device |

**Satu secret dipakai untuk SEMUA:**
```
suomafsehwonhtuoyylraeniemohtfel   (32 byte, dipakai APA ADANYA — bukan dibalik)
```

---

## 2. Formula `clsignature` (BUKTI)

**`clsignature = HMAC-SHA256("suomafsehwonhtuoyylraeniemohtfel", plaintext_body)`**

Bukti (dari HAR, dicocokkan langsung):
```
HMAC(secret, "{}")                                                      = 5f7743c15e481889a818a51a13669e4ae9b893c88add4a9396d5fe7bc3d47506  ✓
HMAC(secret, '{"store_code":"CMH.SPBUCMH"}')                           = a9ded57bb5e006e3e8d5152161c0fcf567c2c726efc5cc497c7da7fee3cb4133  ✓
HMAC(secret, '{"is_login":false,"store_code":null}')                   = b72f629d3238e1d9fa948c8c80fd3c9365e9424b0164181bdfadc093ff024646  ✓
HMAC(secret, '{"phone":"0062...","marketplace_id":90001,...}')         = 2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1  ✓
```
**18/18** request berbody-plaintext cocok persis. Untuk endpoint berbody-terenkripsi (register/login/...), clsignature dihitung atas **plaintext** (sebelum enkripsi) — juga sudah didekripsi & dicocokkan.

Catatan: clsignature **tidak** bergantung pada method, path, deviceid, wtoken, atau timestamp — **hanya plaintext body**. (Login/register sama persis clsignature-nya karena plaintext-nya identik.)

---

## 3. Enkripsi Body (AES — KUNCI DITEMUKAN)

**Algoritma: AES-256-CBC + PKCS7** (bukan GCM seperti dugaan awal).

```
KEY (32 byte) = "suomafsehwonhtuoyylraeniemohtfel"   (= SECRET yg sama)
IV  (16 byte) = "suomafsehwonhtuo"                    (= 16 byte pertama SECRET)
FORMAT wire   = base64( [3 byte random] [0x01 = versi] [AES-256-CBC ciphertext] )
```

Bukti dekripsi sampel HAR:
| Endpoint | Body terenkripsi → plaintext |
|---|---|
| register | `{"phone":"00628XXXXXXXXX","marketplace_id":90001,"new_otp_options":true,"otp_type_code":1002,"new_flow":true}` |
| login | `{"grant_type":"customer","username":"00628XXXXXXXXX","password":"XXXXXX","marketplace_id":90001}` |
| thirdpartyAccountOptions | `{}` |

Cara menemukan kunci: body register-30 vs register-43 menunjukkan byte `[4:]` identik padahal plaintext sama → setelah buang 4-byte prefix, sisa block-aligned (AES-CBC, IV tetap). Lalu AES-ECB-decrypt ct dengan KEY=secret menghasilkan `plaintext XOR IV`, dan IV terungkap = 16 byte pertama secret.

**Endpoint yang mengenkripsi body** (= butuh `wtoken`): register, login, thirdpartyLogin, thirdpartyAccountOptions, verifyPhone, checkPin, sendOtp, changePin, promotion/search, giveGet/createGiveGetRecord, giveGet/claimVoucher. Endpoint lain mengirim plaintext JSON.

---

## 4. Header Request (dari HAR v126.07.23)

```
content-type: application/json
accept: application/json
appid: kopikenangan
deviceid: <16 hex>
devicetype: Android
appsflyer_id: <id>
language: id
version: 126.07.23          versioncode: 375
sign_version: 256            (v126.08.13 = 512 — berubah per versi)
timezone: 25200              (Asia/Jakarta, detik)
user-agent: Dart/3.12 (dart:io)
islogin: false|true
ant_support: true   gopay_v2: true   gopay_v3: true   supportsharebuy: true
clsignature: <HMAC-SHA256>
wtoken: 0004_<hex TigerTally>        (dari device)
cookie: acw_sc__v3=...               (anti-crawler Alibaba, opsional)
```

---

## 5. `wtoken` (TigerTally — input eksternal)

Format di HAR: `0004_<96 hex char>` (contoh: `0004_9FBC216E...`). Dihasilkan native `libtiger_tally.so` via JNI `gsRaw`. app_key = `XSA0N3Mpig...MAqk=`. **Tidak bisa direproduksi Python** — harus diambil dari device (Frida hook `gsRaw`, skrip `frida_kopikenangan.js` sudah ada).

---

## 6. Script `kopken_request.py` — Cara Pakai

```bash
# 0) Self-test (verifikasi rumus, tanpa kirim request)
python3 kopken_request.py --selftest

# 1) Hitung clsignature saja
python3 kopken_request.py --clsig '{"phone":"00628..."}'

# 2) Dekripsi body terenkripsi
python3 kopken_request.py --decrypt "aDQaATyM/lKy...DI+c/o="

# 3) Dry-run (bangun request tanpa kirim)
python3 kopken_request.py --dry-run --phone 006281234567890

# 4) Kirim register sungguhan (BUTUH wtoken dari device!)
python3 kopken_request.py --endpoint "register?android_al_atb=true" \
    --wtoken "0004_ABCD..." --deviceid 60a50f76e17f3dd0 \
    --appsflyer_id "1785...-..." --phone 006281234567890
```

API Python:
```python
from kopken_request import clsignature, encrypt_body, decrypt_body, kk_request
print(clsignature('{"phone":"0062..."}'))      # HMAC-SHA256
print(encrypt_body({"phone":"0062..."}))       # AES-256-CBC -> base64
print(decrypt_body("aDQaATyM..."))             # dekripsi
```

`wtoken` diisi dari device asli (Frida). Tanpa wtoken, endpoint protected akan ditolak server.

---

## 7. File Deliverable (`~/kopken_analysis/`)

| File | Isi |
|---|---|
| `kopken_request.py` | **Script utama** (clsignature + AES + HTTP). Self-test lulus. |
| `FINAL_REPORT.md` | Laporan ini |
| `REPORT.md` | Laporan statis awal (TigerTally, blutter, alamat fungsi) |
| `frida_kopikenangan.js` | Skrip Frida (hook gsRaw/clsignature) |
| `poc_kopikenangan.py` | PoC awal |
| `blutter_out/` | Dump Dart AOT (pp.txt, asm, frida template) |
| `decompiled_java/` | Hasil jadx (TigerTally Java bridge) |
| `kk_requests.json` | Ekstrak 24 request KK dari HAR |

---

## 8. Koreksi temuan sebelumnya

- ❌ Dugaan "AES-GCM" → ✅ Sebenarnya **AES-256-CBC** (ada 4-byte prefix `[rnd3][0x01]` yang sempat menyesatkan analisis panjang).
- ❌ Dugaan "secret dipakai setelah dibalik (`lefthomeinearlyyouthnowhesfamous`)" → ✅ Sebenarnya dipakai **apa adanya**: `suomafsehwonhtuoyylraeniemohtfel` (kalimat terbalik itu memang cara penyimpanan, tapi kode TIDAK membaliknya).
- ❌ Dugaan "clsignature butuh timestamp/nonce" → ✅ Hanya butuh **plaintext body**.
- ✅ AES key = IV = HMAC key = **satu string secret** yang sama.

---

## 9. Catatan Etis & Batasan

- **Jangan** gunakan script untuk membuat akun massal, abuse promo, scraping, atau mengakses server tanpa izin.
- `wtoken` (TigerTally) adalah penghalang utama yang sah — sengaja tidak bisa dipalsukan tanpa device asli.
- Semua verifikasi dilakukan terhadap data capture (HAR), **tidak ada request ke server produksi** yang dikirim dalam analisis ini.
