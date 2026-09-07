# ANALISA `wToken` & `libtiger_tally.so` — Kesimpulan Definitif

> Riset keamanan/edukasi. **Kesimpulan: `wToken` TIDAK dapat direproduksi Python murni.** Harus diambil dari device via MITM proxy (lihat `NO_FRIDA_WTOKEN_GUIDE.md`).

## 1. Hasil analisis `libtiger_tally.so`

| Pemeriksaan | Hasil |
|---|---|
| Tipe file | ELF64 ARM aarch64, stripped, NDK r21e, 4.3 MB |
| Simbol diekspor | **1692 fungsi** dengan **nama acak 10-char** (`GXQPkTqZOh`, `jQd2f2B8fa`, ...) → obfuscasi total |
| Pendaftaran JNI | **Dinamis** via `JNI_OnLoad` (offset `0x128a2c`) + `RegisterNatives` — **tidak ada** simbol `Java_...gsRaw` |
| String sensitif | `gsRaw`/`SecurityNative`/`tigerTally`/`0004`/`app_key` **tidak ditemukan** sebagai plaintext → dienkripsi saat disimpan (decrypted at runtime) |
| Engine C++ | RTTI membocorkan namespace **`NSSecurityDevice`** dengan puluhan class obfuscated (`Asdfibb620`, `Assfgbb320`, ...) |
| Anti-tamper | `N16NSSecurityDevice22WeakClassLoaderVisitorE` — hook ClassLoader Java (integritas) |
| Konstanta crypto standar | **TIDAK ADA** — AES S-box (`637c777b...`), SHA256 K (`428a2f98`), MD5 T (`d76aa478`) semua **NOT FOUND** → algoritma proprietary / konstanta di-decrypt saat runtime |

## 2. Bukti device-fingerprinting (dari import ELF)

Library meng-import fungsi-fungsi Android yang membaca **environment device**:

| Import | Arti |
|---|---|
| `__system_property_get` / `__system_property_read` | baca build properties (ro.build.*, serial, model) |
| `dlopen` | load library dinamis (anti-tamper / introspeksi) |
| `popen` | eksekusi command shell |
| `opendir`/`open`/`fopen`/`fread`/`__open_2`/`__read_chk` | baca filesystem (`/proc`, `/sys`, app list, dll) |
| `pthread_*` | threading untuk fingerprint async |

→ Library mengumpulkan **sidik jari device nyata** (Android ID, build info, sensor, file system, anti-emulator) yang **tidak bisa disimulasikan di Python**.

## 3. Mengapa TIDAK bisa Python murni (alasan teknis kuat)

1. **Crypto proprietary**: tidak ada satu pun konstanta AES/SHA/MD5 standar. Algoritma signature TigerTally custom, di-decrypt & dieksekusi di dalam engine `NSSecurityDevice` yang ter-obfuscate (1692 fungsi).
2. **Device-bound**: payload wToken menyertakan fingerprint device (`9581d311...`) yang dibaca via `__system_property_*` dan filesystem — tidak ada di PC.
3. **Time-bound**: setiap request signature berubah (24/24 sampel unik); memerlukan keystore/TEE-bound secret.
4. **Anti-tamper & anti-emulator**: deteksi hooking (`WeakClassLoaderVisitor`), dan (di Java `s/A.java`) deteksi Xposed/Substrate/Zygote — environment Python tak bisa lolos.
5. **JNI dinamis**: `gsRaw` tak bisa dipanggil langsung via `ctypes` karena tidak diekspor dan butuh `JNI_OnLoad` init + Context Android.

Mencoba mem-port `gsRaw` ke Python = mereimplementasi ribuan fungsi obfuscated + seluruh environment Android. **Tidak praktis.**

## 4. Struktur `wToken` (didecode dari 24 sampel HAR)

```
0004_<HEX_SIG 96char>/<B64_PAYLOAD ~640char>==_<B64_DEVICEID>_<APPINFO>-h-<TIMESTAMP>-<HASH>
```

| Segmen | Contoh | Sifat |
|---|---|---|
| versi | `0004` | konstan |
| HEX_SIG | `9FBC216E...C507` (48 byte) | **berubah per request** |
| B64_PAYLOAD | `BrVWw...==` | data device terenkripsi, berubah per request |
| B64_DEVICEID | base64(`9581d31117855677301363762ee583\|...`) | **konstan per device** |
| TAIL | `e6a858e8bc7bb0f9-h-1785567707291-62b672e1...` | timestamp sesi + hash |

## 5. Solusi praktis (tanpa Frida)

Karena tidak bisa dibuat: **ambil `wToken` via MITM proxy** (`mitmproxy`/Burp) saat app jalan normal — lihat **`NO_FRIDA_WTOKEN_GUIDE.md`**. Lalu tempel/file/`env:` ke `kopken_flow.py`.

> Catatan: wToken time-bound & per-request → ambil **segar** sesaat sebelum dipakai.

## 6. Pendekatan EMULATOR (dari referensi `refrensi.txt`)

`wToken` **bisa** dihasilkan tanpa device nyata dengan **meng-emulasi** `libtiger_tally.so`. Referensi menunjukkan 2 implementasi:

| Tool | Bahasa | OS | Cara |
|---|---|---|---|
| **unidbg** | Java | Android | load `libtiger_tally.so` + APK, mock JNI env (Build.MODEL/BRAND/DEVICE), panggil `_genericNt1(app_key)` init lalu `_genericNt3(data)` → wToken |
| **Chomper** | Python | iOS | load binary, ObjC `AliTigerTally`, `initialize:(app_key)`, `vmpSign:(data)` → wToken |

**Fungsi native kunci (TigerTally Android):**
- `_genericNt1(I,Ljava/lang/String;)I` — init dengan app_key
- `_genericNt3(I,[B)Ljava/lang/String;` — **sign** (input byte[], output wToken)

**Peringatan kritis (penyebab HTTP 405):** wToken mengandung **device fingerprint** dari `android/os/Build` (MODEL/BRAND/DEVICE/RELEASE) + Android-ID. Emulator yang **tidak memock** ini menghasilkan wToken dengan **fingerprint KOSONG** → server menolak (HTTP 405). Lihat §7.

## 7. DIAGNOSA HTTP 405 (kasus wToken emulator)

Perbandingan wToken user vs HAR (device nyata):

| | HAR (BERHASIL) | USER (405) |
|---|---|---|
| segmen fingerprint (base64 decode) | `9581d31117855677301363762ee583\|...` | **`\|\|` (KOSONG)** |
| appinfo hash | `e6a858e8bc7bb0f9` ✓ | `e6a858e8bc7bb0f9` ✓ |
| timestamp | 2026-08-01 | 2026-08-23 10:12 (segar, **tidak expired**) |

**Akar masalah**: wToken user dihasilkan emulator dgn **fingerprint KOSONG** (`||`) → validasi server-side gagal → tolak. Bukan `deviceid` header / kadaluarsa.

`kopken_flow.py` kini punya **health-check wToken** (`wtoken_check()`, menu opsi 10) yang mendeteksi fingerprint kosong & **memblokir kirim nyata**.

**Solusi**: pakai wToken **device NYATA** (MITM proxy). Jika pakai emulator, **wajib mock Build/Android-ID** dgn nilai realistis.
