# PANDUAN REAL TEST — Kopi Kenangan (tanpa Frida)

> ⚠️ **HANYA untuk riset keamanan dengan izin**, di device milik sendiri. Jangan akses server produksi tanpa otorisasi. Panduan ini **tidak menggunakan Frida** — wToken diambil via MITM proxy.

Alur: siapkan device → ambil `wToken` via proxy → jalankan menu interaktif `kopken_flow.py` (register → OTP → login → check promo).

---

## BAGIAN A — PERSIAPAN (sekali saja)

### A1. Device Android
- Rooted (Magisk) atau emulator (Genymotion/LDPlayer/AVD). Root **mempermudah** install CA proxy ke system store.
- Pasang app Kopi Kenangan (v126.07.23 atau 126.08.13).

### A2. ADB & Python di PC
```bash
# ADB (Platform Tools) — pastikan 'adb devices' mendeteksi device
pip install requests pycryptodome mitmproxy
```
File proyek di satu folder: `kopken_flow.py`, (`frida_get_wtoken.py` tidak dipakai lagi).

---

## BAGIAN B — AMBIL `wToken` VIA MITM PROXY

`wToken` (TigerTally) tidak bisa dibuat Python — intersepsi saat app jalan normal. (Detail lengkap: `NO_FRIDA_WTOKEN_GUIDE.md`.)

### B1. Jalankan proxy di PC
```bash
mitmdump -p 8080 --set flow_detail=2
```
Catat IP PC di jaringan yang sama (mis. `192.168.1.5`).

### B2. Arahkan device ke proxy
WiFi → Modify network → Proxy = Manual → host `IP_PC`, port `8080`.

### B3. Install CA proxy sebagai trusted (perlu root paling mudah)
- Browser device → `http://mitm.it` → unduh cert Android.
- Install ke **system store** (Android ≥7 wajib system store untuk app):
```bash
HASH=$(openssl x509 -in mitmproxy-ca-cert.pem -inform PEM -subject_hash_old | head -1)
adb push mitmproxy-ca-cert.pem /sdcard/$HASH.0
adb shell "su -c 'mount -o remount,rw /system && cp /sdcard/$HASH.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/$HASH.0'"
adb shell "su -c 'mount -o remount,ro /system'"
```
- Tes: buka situs HTTPS di browser device → tanpa peringatan.

### B4. Tangkap wToken + deviceid + appsflyer_id (SEKALIGUS, dari request yang sama!)
1. Buka app Kopi Kenangan → Register/Login (masukkan nomor HP).
2. Di log `mitmdump`, cari request `apps.kopikenangan.com` (mis. register/login). **Dari request yang SAMA**, salin TIGA nilai header:
   ```
   wtoken: 0004_9FBC216E...........................==
   deviceid: 60a50f76e17f3dd0
   appsflyer_id: 1785567706719-1951644852348616957
   ```
3. Simpan ketiganya (mis. `wtoken.txt`, catat deviceid/appsflyer_id). **Ketiganya HARUS dari device & request yang sama.**
4. **Cek kesehatan wToken** sebelum dipakai:
   ```bash
   python3 kopken_flow.py   # menu → pilih 10 (cek wToken)
   ```
   Jika `fingerprint = '||'` (KOSONG) → wToken dari emulator tanpa device info → server **menolak (HTTP 405)**. Pakai wToken device NYATA.
5. Jangan tutup app sampai selesai (cookie WAF `acw_sc__v3` + sesi aktif).

> Jika request tidak muncul di proxy → kemungkinan SSL pinning (lihat `NO_FRIDA_WTOKEN_GUIDE.md` §C). Dari HAR, Kopi Kenangan tampaknya **tidak pinning**.

---

## BAGIAN C — JALANKAN ALUR (menu interaktif)

### C1. Mulai
```bash
python3 kopken_flow.py
```
Menu muncul. Saat prompt awal:
- **wToken**: `file:wtoken.txt` (atau tempel / `env:WTOKEN`).
- **DeviceId / appsflyer_id**: Enter untuk default.
- **Nomor HP**: nomor uji milik sendiri (`0062...`).

### C2. Register
- Pilih **1**. Default = SIMULASI. Untuk kirim nyata: pilih **9** → ketik `YA-SAYA-PASTI`.
- Respons sukses: `"otp_sent":true` → **OTP via SMS** ke nomor HP.

### C3. Ambil OTP dari SMS (6 digit).

### C4. Login
- Pilih **2** → nomor HP sama + OTP sebagai password.
- Respons: `"is_success":true` + `access_token` (JWT, disimpan otomatis).

### C5. Check Welcome Package
- Pilih **3** (pakai JWT otomatis). Contoh: `{"msg":"...sudah pernah melakukan transaksi"}`.

---

## BAGIAN D — EQUIVALEN CLI

```bash
# Kirim satu request register (wToken+deviceid+appsflyer_id dari proxy, request yang sama):
python3 kopken_flow.py --step register --send --phone 00628XXXXXXXXX \
    --wtoken file:wtoken.txt \
    --deviceid 60a50f76e17f3dd0 \
    --appsflyer-id 1785567706719-1951644852348616957

# Alur penuh:
python3 kopken_flow.py --flow --send --phone 0062812XXXXXXXX --otp 123456 \
    --wtoken file:wtoken.txt --deviceid 60a50f76e17f3dd0

# Cek kesehatan wToken dulu (deteksi fingerprint kosong penyebab 405):
python3 kopken_flow.py --step register --dry-run --wtoken file:wtoken.txt
```
**Yang dicek setelah register:** respons harus JSON dengan `otp_sent:true`. Script kini **mencetak body respons penuh** jika status bukan JSON 200 (debug WAF/405). Jika respons HTML `aliyun_waf_aa` atau status 405 → lihat troubleshooting.

---

## BAGIAN E — TROUBLESHOOTING

| Gejala | Solusi |
|---|---|
| Respons HTML (`aliyun_waf_aa`) atau **HTTP 405** | wToken bermasalah: **fingerprint kosong** (`||`, dari emulator tanpa device info) ATAU expired. Cek via menu opsi 10. Ambil ulang wToken dari device NYATA via proxy. |
| `fingerprint = '||'` saat cek wToken | wToken dari emulator (unidbg/Chomper) tanpa mock Build. Wajib mock Build.MODEL/BRAND/DEVICE + Android-ID, atau pakai device nyata. |
| Request tidak muncul di proxy | SSL pinning aktif → lihat `NO_FRIDA_WTOKEN_GUIDE.md` §C (patch APK). |
| Browser device tidak bisa `http://mitm.it` | Proxy belum aktif / salah port. Cek setingan proxy WiFi. |
| Sertifikat tidak terpercaya di app | CA belum masuk **system store** (root), atau Android ≥7 needs system CA. |
| OTP tidak diterima | Nomor salah format / sudah pernah daftar → coba login langsung (menu 2). |
| `InsecureRequestWarning` | Hanya peringatan SSL, aman diabaikan. |

---

## CHECKLIST AKHIR
- [ ] adb devices → device muncul
- [ ] mitmproxy jalan, CA terinstall di system store device
- [ ] app Kopi Kenangan → request muncul di proxy → wToken tersalin ke `wtoken.txt`
- [ ] `python3 kopken_flow.py --selftest` → semua PASS
- [ ] `python3 kopken_flow.py` menu → Register → `otp_sent:true`
- [ ] SMS OTP diterima
- [ ] Login → `is_success:true` + access_token
- [ ] Check Welcome → JSON respons
