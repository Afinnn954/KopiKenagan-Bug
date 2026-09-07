# PANDUAN AMBIL `wToken` TANPA FRIDA (MITM Proxy)

> Riset keamanan/edukasi dengan izin, di device milik sendiri. `wToken` (TigerTally) tidak bisa dibuat Python (lihat `WT_TOKEN_ANALYSIS.md`) — cara termudah mengambilnya: **intersepsi header via MITM proxy**.

## Konsep singkat
Pasang proxy MITM di PC → arahkan traffic device ke proxy → install sertifikat CA proxy sebagai *trusted* di device → buka app Kopi Kenangan → header `wtoken` akan tampil di log proxy (karena dekripsi TLS terjadi di proxy).

## A. Alat yang dipakai
- **mitmproxy** (rekomendasi, gratis, CLI): `pip install mitmproxy`
- Alternatif: **Burp Suite Community** (GUI).

## B. Langkah-langkah (mitmproxy)

### B1. Jalankan proxy di PC
```bash
pip install mitmproxy
mitmdump -p 8080 --set flow_detail=2
```
Catat **IP PC** di jaringan yang sama dengan device (mis. `192.168.1.5`). Cek: `ip addr` / `ipconfig`.

### B2. Set proxy di device Android
- **WiFi** → sentuh lama jaringan terhubung → **Modify network** → **Advanced/Proxy** → **Manual**:
  - Proxy hostname: `IP_PC` (mis. `192.168.1.5`)
  - Proxy port: `8080`
  - Save.
- (Emulator: bisa juga set via Settings atau `adb shell settings put global http_proxy IP_PC:8080`.)

### B3. Install sertifikat CA mitmproxy (agar TLS bisa di-decode)
1. Di device, buka browser → kunjungi **`http://mitm.it`** (harus muncul saat proxy aktif).
2. Pilih **Android** → unduh `mitmproxy-ca-cert.pem`.
3. **Android ≥ 7**: CA user tidak dipercaya untuk app secara default. Anda butuh salah satu:
   - **Root** (paling mudah): install CA ke *system store*:
     ```bash
     # di PC, hash nama file sesuai aturan Android
     adb push mitmproxy-ca-cert.pem /sdcard/
     adb shell "su -c 'cp /sdcard/mitmproxy-ca-cert.pem /system/etc/security/cacerts/c8750f0d.0 && chmod 644 /system/etc/security/cacerts/c8750f0d.0'"
     # (nama hash 8-hex bisa beda; gunakan 'openssl x509 -subject_hash_old' untuk dapat nama)
     ```
   - Atau aktifkan **"Use user credentials in apps"** (Android 14+) di Settings → Security.
4. Verifikasi: buka situs HTTPS di browser device → tidak ada peringatan sertifikat.

### B4. Tangkap `wToken`
1. Buka **app Kopi Kenangan**, lakukan **Register** atau **Login** (masukkan nomor HP).
2. Di terminal `mitmdump`, cari request ke `apps.kopikenangan.com`. Header akan terlihat:
   ```
   POST https://apps.kopikenangan.com/kk-api-kopikenangan/register?android_al_atb=true
   ...
   wtoken: 0004_9FBC216E.....................................................==
   clsignature: 2282f0aa...
   ```
3. Salin **nilai penuh** `wtoken` (mulai `0004_...`) → simpan ke `wtoken.txt`.

> **Filter cepat** untuk hanya lihat header wtoken:
> ```bash
> mitmdump -p 8080 --set flow_detail=0 \
>   --filter-d '~d apps.kopikenangan.com' \
>   -e 'print(flow.request.headers.get("wtoken"))'
> ```

## C. Jika gagal (kemungkinan SSL Pinning)
- Gejala: request ke `apps.kopikenangan.com` **tidak muncul** di proxy (atau app error koneksi).
- Artinya app melakukan **SSL pinning** (tidak mempercayai CA user).
- **Dari sampel HAR**, Kopi Kenangan **tampaknya TIDAK pinning** (HAR berhasil menangkap HTTPS penuh). Jadi kemungkinan besar proxy akan jalan.
- Jika ternyata pinning: opsi sah (di device milik sendiri) = patch APK untuk menonaktifkan pinning via `apk-mitm`/`objection`, lalu pasang ulang. Ini di luar panduan ini.

## D. Pakai `wToken` di script
```bash
# Tempel langsung:
python3 kopken_flow.py --flow --send --phone 0062812XXXXXXXX --wtoken "0004_..."

# Dari file (hasil salin proxy):
python3 kopken_flow.py --flow --send --phone 0062812XXXXXXXX --wtoken file:wtoken.txt

# Dari environment variable:
export WTOKEN="0004_..."
python3 kopken_flow.py --flow --send --phone 0062812XXXXXXXX --wtoken env:WTOKEN
```
Atau dari **menu interaktif** (`python3 kopken_flow.py`) → ketik `file:wtoken.txt` saat diminta wToken.

## E. Catatan penting
- `wToken` **time-bound & per-request** → ambil segar (<60 detik sebelum dipakai).
- Endpoint sensitif (register/login) kemungkinan menuntut wToken baru; endpoint biasa menoleransi wToken sesi.
- Jangan bagikan `wToken` berisi fingerprint device Anda ke pihak lain.
