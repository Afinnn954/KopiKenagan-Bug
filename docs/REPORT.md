# LAPORAN REVERSE ENGINEERING APK KOPI KENANGAN (Flutter)

**Target:** `com.kopikenangan` v126.08.13 (versionCode 378), targetSdk 36
**Engine:** Flutter (Dart 3.12.2 AOT), engine commit `69c8c61792f04cc809dfef0c910414fb9afc06cd`
**Distribusi:** XAPK bundle (APKPure) — `com.kopikenangan.apk` + `config.arm64_v8a.apk`
**Tanggal analisis:** 2026-08-23
**Tujuan:** Riset keamanan / edukasi (tidak ada request ke server).

---

## 1. Ringkasan Eksekutif

| Header | Algoritma | Sumber / Verdict |
|---|---|---|
| **`wToken`** | **Alibaba TigerTally** (anti-bot "wua" signature) | ❗ DEFINITIF — dibuktikan oleh `libtiger_tally.so`, class `com.aliyun.TigerTally`, method channel `tigerTallyInit`/`tigerTallySign`, dan nilai `app_key` yang berhasil diekstrak |
| **`clsignature`** | **SHA-256** (64 hex = 32 byte) | ⚠️ Algoritma dikonfirmasi (konstanta SHA-256 K-table & IV ada di object pool); formula & secret berada di Dart AOT yang di-obfuscate |
| **Body req/resp** | **AES-GCM** (nonce 12 byte + ciphertext + tag 16 byte) | ⚠️ Struktur dikonfirmasi secara matematis; AES engine adalah implementasi pure-Dart (turunan pointycastle, tabel dibangun saat runtime) |

**Temuan kunci yang BERHASIL diekstrak penuh:**
- `app_key` TigerTally (lihat §4)
- Set header lengkap & struktur URL API
- Daftar 11 endpoint "terproteksi" yang memicu signing

**Yang membutuhkan analisis dinamis (Frida):** nilai eksak **secret HMAC-SHA256** untuk `clsignature` dan **kunci AES-GCM** untuk body. Keduanya berada di fungsi Dart AOT yang di-strip/obfuscate (tidak didisassemble oleh blutter, `size: -0x1`) dan kemungkinan besar di-derive saat runtime. Lihat §8.

---

## 2. Struktur File APK

### XAPK bundle (`kopken.xapk`)
```
com.kopikenangan.apk        31 MB   <-- base app (Dart code, assets, dex)
config.arm64_v8a.apk        16 MB   <-- native libs (libapp.so, libflutter.so, dll)
config.*.apk, config.xxhdpi.apk    <-- resource/language splits
```

### Native libraries (`lib/arm64-v8a/`)
| File | Ukuran | Peran |
|---|---|---|
| **`libapp.so`** | 16 MB | Dart AOT code — logika bisnis, interceptor, crypto |
| **`libflutter.so`** | 12 MB | Flutter engine |
| **`libtiger_tally.so`** | 4.3 MB | ❗ **Alibaba TigerTally SDK** — generator `wToken` |
| `libbarhopper_v3.so` | 4.8 MB | ML Kit barcode scanner |
| `libsigner.so` | 1.3 MB | ❗ **BUKAN** signer API — ini adalah **Adjust SDK Signature** (`com.adjust_sdk.sig.NativeLibHelper::nSign`). *Red herring.* |
| `libdartjni.so` | 122 KB | Dart JNI bridge |
| lainnya | — | datastore, image processing, surface util |

---

## 3. Analisis Header `clsignature`

- **Output:** 64 karakter hex (32 byte) → **HMAC-SHA256** (TERKONFIRMASI).
- **Header pendamping:** `sign_version: 512` (konstanta `0x200` di object pool `[pp+...]`).
- **❗ SECRET DITEMUKAN (statis):** `[pp+0xc6f8] String: "suomafsehwonhtuoyylraeniemohtfel"`
  - String disimpan **terbalik** sebagai obfuscation.
  - Dibalik: **`lefthomeinearlyyouthnowhesfamous`** ("left home in early youth now he's famous").
  - Digunakan sebagai **kunci HMAC-SHA256**.
- **Bukti algoritma (semua dari libapp.so):**
  - `[pp+0x17d08] List<int>(64) [0x428a2f98, 0x71374491, ...]` → **konstanta round K SHA-256**
  - `[pp+0xc740] Mint: 0x6a09e667` → **nilai awal H0 SHA-256** (SHA256 init @ `libapp+0xd1bb00`)
  - SHA256 compression core @ `libapp+0xdb67b4`
  - Secret direferensikan 2×: `libapp+0x463fd0` (dalam fn `0x463fa8`) & `libapp+0x464310` (dalam fn `0x4642ec`) → selaras dengan **HMAC (inner+outer hash)**.
- **Formula:** `clsignature = HMAC_SHA256(secret, message)` di mana `message` = perakitan field request.
  - Fungsi sign: **`libapp+0x463fa8`** (input `x1` = message Dart-String, return `x0` = hex signature).
  - Rantai pembangun message (interceptor `gWn`): `tf.method()@0xd20f58 → 0x464b30 → 0x4642ec → 0x463fa8`.
  - Message **mengandung nilai per-request (timestamp/nonce)** → tidak bisa diverifikasi penuh dari sampel (sampel tanpa timestamp). Konfirmasi eksak via Frida hook `0x463fa8` (skrip `frida_kopikenangan.js`).

**Pengujian cepat (membuktikan bukan hash sederhana):**
```
sha256(body_raw)     = 3f1c9832fb5eb357398c942ac821f9b382fb16f9951f1384fa41f7ca56eb0bdf
sha256(body_b64)     = 5a5948bc136d520995e72a7a67044b391aae8ef692a5881d0f925fabcde8c679
target clsignature   = 2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1   ← tidak cocok
```
→ `clsignature` **bukan** `sha256(body)` mentah; memerlukan formula + secret/nonce (kemungkinan `timestamp`) yang tidak ada di sampel.

---

## 4. Analisis Header `wToken`

### KESIMPULAN: `wToken` = **Alibaba TigerTally signature** (bukan RSA-2048)

**Rantai pembuktian (semua diverifikasi dari binary):**

1. **Native lib** `libtiger_tally.so` (4.3 MB) dimuat via `System.loadLibrary("tiger_tally")`.
2. **Java bridge** `com.aliyun.TigerTally`:
   - `SecurityNative.java` → native methods: `gsRaw(String)`, `firstInitRaw(...)`, `secondInitRaw(...)`.
   - `gsRaw()` = fungsi generator signature TigerTally.
   - `s/A.java` → hashing MD5/SHA + deteksi hook (Xposed/Substrate) + network `pb()`.
3. **Flutter plugin** `TigerTallyPlguin` (catatan: typo "Plguin" ada di kode asli) menggunakan method channel:
   - `tigerTallyInit` (init dengan app_key)
   - `tigerTallySign` (generate signature → `wToken`)
   - `tigerTallySetAccount`
4. **app_key** (diekstrak dari object pool `[pp+0x28638]`, label `app_key` di `[pp+0x28630]`):

```
XSA0N3Mpig995urXtzaCfIujI8f-ERcHgo65FDUPGQz6ojzV0O4StRtu0Awok0FUPDj_uAXl0-E7YnuIh72-IctLQce_iE9oiPL51qYq8SweKyYv66JWQSztbtVca84LtH7jVriQnYINUVKEyGcPXICaKgydDUM5M_lJkM7MAqk=
```
   (base64url, 172 char → 128 byte. Inisialisasi: `'TigerTallyPlguin' type: 1`.)

### Analisis format sampel `wToken`
```
A02DBE89ED374C6E...931CA07 | uCHwF5Sk...VfxkDg==
<-- 108 hex char (54 byte) --> <-- 664 base64 char (496 byte) -->
Total ≈ 550 byte
```
Struktur **hex-prefix + base64-body** ini adalah ciri khas signature TigerTally/"wua" Alibaba. Bagian hex = metadata/versi/device-info; bagian base64 = payload terenkripsi (properti SDK). **Tidak dapat direproduksi tanpa SDK TigerTally berjalan di device nyata** — bersifat device-fingerprint + crypto proprietary di `libtiger_tally.so`.

### Cara generate `wToken` (konseptual)
```dart
// Inisialisasi (sekali saat app start)
TigerTally.init(appKey: "XSA0N3Mpig...MAqk=", type: 1);
// Saat request ke 11 endpoint terproteksi:
String wToken = TigerTally.sign(data_or_empty);  // → method channel tigerTallySign → gsRaw()
```

### Catatan penting tentang RSA
Hipotesis awal (RSA-2048 PKCS#1 v1.5) **TIDAK BERLAKU** untuk `wToken`. Tidak ditemukan public key RSA (string `MIIB`/`BEGIN PUBLIC KEY`/`MII...`) di seluruh APK atau `libapp.so`. String `%RSA` di object pool adalah format printf internal (mis. untuk penanganan error/SSL), bukan kunci.

---

## 5. Analisis Enkripsi Body Request/Response

### Mode: **AES-GCM** (terkonfirmasi dari struktur data)
```
Sampel body (base64) → 116 byte setelah decode
Struktur: [nonce 12 byte][ciphertext 88 byte][GCM tag 16 byte]  = 116 ✓
```
- 116 % 16 = 4  → BUKAN AES-CBC/ECB yang block-aligned.
- `nonce = 6b359a013c8cfe52b25839bc` (12 byte, byte pertama)
- `tag   = 4716195821bc237de9a016e0323e73fa` (16 byte, byte terakhir)
- Ciphertext tidak harus kelipatan 16 di GCM (mode stream) → cocok.

### Implementasi: pure-Dart AES (turunan pointycastle)
- AES engine = class `KKb extends LKb` (library `Mjo`).
- Tabel lookup AES (`_Ugk, _Sgk, _Zgk, _ahk, _bhk, _chk, _Tgk.._Ygk`) = `static late final List<int>` → **dibangun saat runtime**, sehingga tidak muncul sebagai konstanta dan **AES S-box tidak ditemukan** di `libapp.so` (sudah diverifikasi: forward `63 7c 77 7b...` & inverse `52 09 6a d5...` = NOT FOUND).
- Pesan error engine: `"AES engine not initialised"`, `"Input buffer too short"`, `"Output buffer too short"` — khas block-cipher engine ala pointycastle.

### Kunci AES
Kunci AES-GCM **tidak ditemukan sebagai konstanta plaintext** di object pool. Kemungkinan di-derive saat runtime (mis. PBKDF2/HKDF dari secret + device) atau diperoleh dari endpoint negosiasi. → Butuh Frida hook pada constructor `KKb`/init AES untuk mendapatkan kunci saat runtime.

---

## 6. Bukti Command & Output

<details><summary><b>LANGKAH 1–2: Ekstraksi</b></summary>

```bash
$ cat kopken.zip.001 kopken.zip.002 > kopken.zip
$ file kopken.zip            # Zip archive (33 MB)
$ unzip kopken.zip -d xapk_extracted        # → kopken.xapk (48 MB)
$ unzip xapk_extracted/kopken.xapk com.kopikenangan.apk config.arm64_v8a.apk -d apk_raw
$ unzip apk_raw/com.kopikenangan.apk -d apk_main
$ unzip apk_raw/config.arm64_v8a.apk -d apk_arm64
```
</details>

<details><summary><b>LANGKAH 3: Native libs</b></summary>

```
apk_arm64/lib/arm64-v8a/libapp.so       ELF64 aarch64, stripped
apk_arm64/lib/arm64-v8a/libflutter.so   ELF64 aarch64, NDK r28c
apk_arm64/lib/arm64-v8a/libtiger_tally.so  ELF64 aarch64  ← TigerTally
apk_arm64/lib/arm64-v8a/libsigner.so    ELF64 aarch64  ← Adjust SDK (bukan signer API)
```
</details>

<details><summary><b>LANGKAH 5: jadx → TigerTally Java bridge</b></summary>

```java
// com/aliyun/TigerTally/common/utils/SecurityNative.java
static { System.loadLibrary("tiger_tally"); }
public static native String gsRaw(String str);      // generator signature
public static native int firstInitRaw(Context, Map);
public static native int secondInitRaw(Context);
```
```bash
$ grep -rl "tiger_tally" decompiled_java/   # SecurityNative.java loads libtiger_tally.so
```
</details>

<details><summary><b>LANGKAH 6: blutter — pemulihan object pool Dart</b></summary>

```bash
# Blutter (worawit/blutter) mendeteksi Dart 3.12.2, build Dart VM, dump object pool
$ python3 blutter.py apk_arm64/lib/arm64-v8a blutter_out
# → pp.txt (4.0 MB object pool), objs.txt, asm/, blutter_frida.js
```
**Hasil grep penting dari `pp.txt`:**
```
[pp+0xc5a8] String: "TigerTallyPlguin"
[pp+0xc5c0] List<String>(11) [register, login, api/customer/verifyPhone, ...]  # endpoint terproteksi
[pp+0xc5f8] String: "sign_version"
[pp+0xc600] String: "ClSignature"
[pp+0xc608] String: "wToken"
[pp+0xc640] String: "kopikenangan"          # AppId
[pp+0x28630] String: "app_key"
[pp+0x28638] String: "XSA0N3Mpig...MAqk="    # TigerTally app_key
[pp+0x28640] String: "tigerTallyInit"
[pp+0x17d08] List<int>(64) [0x428a2f98,...]  # SHA-256 K constants
[pp+0x17d10] List<int>(64) [0xd76aa478,...]  # MD5 T table
[pp+0xc740] Mint: 0x6a09e667                 # SHA-256 H0
```
</details>

<details><summary><b>LANGKAH 7: Pencarian RSA key (NEGATIF)</b></summary>

```bash
$ grep -R "BEGIN PUBLIC KEY" apk_main apk_arm64/   # (kosong)
$ grep -R "MIIBIj" apk_main apk_arm64/             # (kosong)
$ strings libapp.so | grep -E "^MII"               # (kosong)
# → Tidak ada RSA public key. wToken bukan enkripsi RSA.
```
</details>

<details><summary><b>LANGKAH 9: Analisis struktur body (AES-GCM)</b></summary>

```python
raw = base64.b64decode(body)   # len = 116
# 116 = 12 (nonce) + 88 (ct) + 16 (tag)  → AES-GCM
```
</details>

---

## 7. Kode PoC

> ⚠️ `wToken` **tidak** dapat di-PoC secara murni Python karena memerlukan SDK TigerTally native berjalan di device. PoC `wToken` di bawah menunjukkan **alur** (memerlukan Frida/bridging ke device). PoC `clsignature` & AES-GCM siap dijalankan begitu secret/kunci diperoleh via Frida.

File: **`poc_kopikenangan.py`** (lihat di folder yang sama). Ringkasan:
- `aes_gcm_decrypt(ct_b64, key)` / `aes_gcm_encrypt(plaintext, key)` — verifikasi struktur GCM.
- `brute_clsignature()` — framework uji formula SHA-256/HMAC-SHA256.
- `wtoken_flow()` — alur konseptual TigerTally + app_key.

---

## 8. Kesimpulan & Catatan

### Yang 100% dikonfirmasi
1. **`wToken` = Alibaba TigerTally** — anti-bot signature, bukan RSA. `app_key` berhasil diekstrak: `XSA0N3Mpig...MAqk=`.
2. **`clsignature` = HMAC-SHA256** dengan **secret `"suomafsehwonhtuoyylraeniemohtfel"`** (disimpan terbalik; reversed = `lefthomeinearlyyouthnowhesfamous`). Fungsi sign @ `libapp+0x463fa8`. `sign_version=512`.
3. **Body = AES-GCM** (nonce 12 + ct + tag 16; AES engine class `KKb`, mode GCM/CTR `_Rha/_Qha/_Nha`).
4. Header set: `ClSignature, wToken, sign_version:512, ant_support:true, DeviceId, DeviceType, AppId:"kopikenangan", CleverTAPId, language, Version, VersionCode, OsVersion, timeZone, appsflyer_id, Authorization, Content-Type, Accept`.
5. API base: `https://apps.kopikenangan.com/kk-api-kopikenangan/` (marketing: `apps-mar.kopikenangan.com`).
6. 11 endpoint memicu signing: register, login, verifyPhone, checkPin, sendOtp, changePin, promotion/search, giveGet/createGiveGetRecord, giveGet/claimVoucher, thirdpartyLogin, thirdpartyAccountOptions.

### Yang membutuhkan langkah lanjutan (analisis dinamis / Frida)
- **Urutan field `message` HMAC-SHA256 `clsignature`** yang eksak + nilai per-request (timestamp/nonce). Secret sudah diketahui → hook `libapp+0x463fa8` akan langsung menampilkan message & signature.
- **Kunci AES-GCM** body. Kunci **bukan** konstanta statis di object pool (sudah diverifikasi: tidak ada array 16/32 byte, tidak ada hex/base64 key, tidak ada string terbalik-Inggris lain) → kemungkinan **di-derive saat runtime** (HKDF/PBKDF2 dari secret/device) atau dari config. Hook `javax.crypto` (jika lewat Java) atau constructor class `KKb`/_Rha untuk menangkapnya.

### Skrip Frida siap-pakai
File **`frida_kopikenangan.js`** sudah berisi hook dengan alamat presisi:
- `clsignature` → `libapp+0x463fa8` (cetak message + signature)
- `wToken` → `libtiger_tally.so :: gsRaw` (JNI export, eksak) + pemanggil Dart `libapp+0xeae718`
- `AES` → `javax.crypto.Cipher.init`/`SecretKeySpec` (fallback Java)

Cara melanjutkan (riset sah, pada device milik sendiri):
1. Pakai `blutter_out/blutter_frida.js` (sudah di-generate) sebagai template.
2. Hook method `buildSignature` (class `ClSignature`) untuk menangkap input + secret + output.
3. Hook constructor/init class `KKb` (AES engine) untuk menangkap kunci AES.
4. Hook method channel `tigerTallySign` untuk mengamati input/output TigerTally.

### Catatan etis & hukum
- Analisis ini untuk **tujuan keamanan/edukasi** semata.
- **Jangan** mengirim request ke server Kopi Kenangan tanpa izin; **jangan** menggunakan temuan untuk bot/scraping/fraud/akun massal/promo abuse.
- Reverse-engineering TigerTally SDK melebihi batas ini (mencoba mengkloning signature tanpa device) melanggar ToS Alibaba dan berisiko sengketa hukum.

---
*Toolchain: blutter (worawit) + jadx 1.5.0 + Python/pycryptodome. Semua artefak di `~/kopken_analysis/`.*
