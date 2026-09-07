# ANALISA MENDALAM: Bisakah `wToken` TigerTally Dibuat di Python?

> Riset keamanan/edukasi. Berdasarkan analisis `libtiger_tally.so`, struktur wToken dari HAR, + studi literatur (GitHub, CSDN, Tencent Cloud, cnblogs, 91fans).

## TL;DR (jawaban singkat)

| Pendekatan | Bisa? | Catatan |
|---|---|---|
| **Python murni (crypto saja)** | ❌ **TIDAK** (untuk versi 0004) | Algoritma VMP-obfuscated (16 cipher + SHA256 modifikasi), belum pernah di-"纯算" publik untuk 0004. Hanya versi **lama 0003** (Nike/SNKRS 2024) yang berhasil direstorasi tim khusus (closed-source). |
| **Python + emulator (unidbg/Chomper)** | ⚠️ **Sebagian** | Bisa memanggil `.so` tapi **WAJIB** menyelesaikan **registrasi device ke server Alibaba** (`pb()`) untuk dapat fingerprint token. Tanpa itu → fingerprint kosong → 405. |
| **"Generate device" sintetis di Python** | ❌ **TIDAK cukup** | Device fingerprint `9581d311...` **bukan** dibuat lokal — dikembalikan oleh **server Alibaba** lewat call `pb()` saat `_genericNt1`. |
| **Capture dari device nyata (MITM)** | ✅ **Paling praktis** | wToken valid & lengkap (fingerprint terisi). |

---

## 1. Cara kerja wToken (from multiple sources)

wToken = signature anti-bot Alibaba TigerTally. **4 bagian** [5](https://blog.csdn.net/boshijingang/article/details/127928036):
```
0004_<signature_hex>/<payload_encrypted>==_<device_fingerprint>_<appinfo>-h-<timestamp>-<hash>
```
Payload terenkripsi berisi: device + system + network info [5](https://blog.csdn.net/boshijingang/article/details/127928036).

### Flow generasi (3 fungsi native) [1](https://cloud.tencent.com/developer/article/1926696) [3](https://www.cnblogs.com/2014asm/p/15729919.html):
```
_genericNt2(appkey)  →  DECRYPT appkey
       ↓
_genericNt1(...)     →  kumpulkan info device (Build.*, sensor, Android-ID)
                     →  *** NETWORK CALL ke server Alibaba (pb()/postnet) ***
                     →  DAFTARKAN device → terima FINGERPRINT TOKEN dari server
                     →  cache token sbg SharedPreferences "tt_ak" (^ts^ttl)
       ↓
_genericNt3(data)    →  SIGN:
       message = request_body + SERVER_FINGERPRINT + device_risk + CRC + random
       hasil  = 0004_<sig>/<enc_payload>_<devfp>_<appinfo>-h-<ts>-<hash>
```

## 2. Penyebab wToken user GAGAL (HTTP 405) — bukti dari struktur

| Segmen | HAR (BERHASIL) | USER (405) |
|---|---|---|
| device fingerprint | `9581d31117855677301363762ee583\|...` | **`\|\|` KOSONG** |
| timestamp | 2026-08-01 | 2026-08-23 (segar) |

**Akar masalahnya: fingerprint kosong.** Dari riset: fingerprint itu **token dari server Alibaba** (dari call `pb()`). User membuat wToken via emulator yang **tidak menyelesaikan registrasi server** (`pb()` di-mock kosong) → fingerprint `||` → server **menolak (405)**.

> Jadi bukan masalah: deviceid header, clsignature (sudah benar), atau kadaluarsa (timestamp segar). **Intinya: fingerprint token server tidak diperoleh.**

## 3. Algoritma internal (mengapa "纯算"/Python-murni sangat sulit)

Dari analisis `libtiger_tally.so` + literatur [1](https://cloud.tencent.com/developer/article/1926696) [4](https://rivers.chaitin.cn/blog/cq94imh0lnechd243ffg):
- **16 algoritma enkripsi** dipilih berdasarkan byte padding → tidak ada satu pun konstanta standar (AES S-box, SHA256 K) ditemukan di binary (semua VMP-obfuscated / runtime-decrypted).
- **SHA256 modifikasi** + hash custom [4](https://blog.csdn.net/irabbit666/article/details/128398448).
- **Anti-deteksi**: emulator, proxy, root, debug, hook (Frida/Xposed), multi-open [1](https://cloud.tencent.com/developer/article/1926696).
- 1692 fungsi dengan nama acak (obfuscasi total), engine C++ `NSSecurityDevice`.

**Hanya versi 0003** (Nike/SNKRS, 2024) yang pernah berhasil direstorasi "纯算" (pure-algorithm) oleh tim khusus [4](https://blog.csdn.net/irabbit666/article/details/128398448) — dan **closed-source**. Versi **0004** (Kopi Kenangan) belum pernah dipublikasikan.

## 4. Mengapa "generate device di Python" tidak cukup

User bertanya: bisakah dengan generate device sintetis di Python? Jawabannya: **tidak cukup**, karena:

1. Fingerprint `9581d311...` **bukan** dihitung lokal — itu **token dari server Alibaba** (hasil registrasi device lewat `pb()`).
2. Permintaan registrasi itu sendiri **juga ditandatangani & dienkripsi** oleh `.so` (algoritma obfuscated).
3. Jadi rantainya: generate device info → (via .so) sign registrasi → POST ke server Alibaba → terima fingerprint token → (via .so) sign data → wToken. **Setiap langkah "via .so" butuh emulator.**

## 5. Jalur yang REALISTIS

### Jalur A — Capture dari device nyata (MITM proxy) — ✅ DIREKOMENDASIKAN
- wToken lengkap (fingerprint terisi), valid, segar.
- Lihat `NO_FRIDA_WTOKEN_GUIDE.md` & `REAL_TEST_GUIDE.md`.
- **Batas**: time-bound → ambil segar sebelum dipakai.

### Jalur B — unidbg (Java) + selesaikan registrasi server — ⚠️ Sulit
- Set up unidbg, load `libtiger_tally.so` + APK Kopi Kenangan.
- Mock JNI env (Build.MODEL/BRAND/DEVICE realistis).
- **Jangan mock `pb()` kosong** — biarkan `.so` benar-benar POST ke server Alibaba untuk dapat fingerprint (`9581d311...`). Ini butuh koneksi keluar + identitas device yang lolos anti-emulator.
- Referensi kode: `refrensi.txt` (TigerTally.java), [3](https://www.cnblogs.com/2014asm/p/15729919.html), [ibox example](https://www.jianshu.com/p/d4c6cb0b639c).
- **Masalah**: anti-emulator detection bisa membuat server menolak registrasi → fingerprint tetap kosong → 405 (persis yang terjadi pada user).

### Jalur C — Chomper (Python, iOS) — ⚠️ Hanya untuk target iOS
- Python, tapi untuk binary **iOS** (`AliTigerTally` ObjC), bukan Android `libtiger_tally.so` [refrensi.txt baris 1-28].
- Untuk Kopi Kenangan (Android) tidak langsung berlaku.

### Jalur D — Frida RPC / AndServer RPC di device nyata — ✅ Reliabel
- Pakai device nyata, panggil SDK lewat RPC (lihat [1](https://cloud.tencent.com/developer/article/2016900) untuk pola `_genericNt3` RPC).
- Fingerprint selalu valid (device nyata).

## 6. Kesimpulan akhir

1. **Python murni (tanpa emulator/server) TIDAK BISA** membuat wToken valid untuk versi 0004. Algoritma obfuscated & belum publik.
2. **Blokernya bukan "device generation"** — blokernya adalah **fingerprint token yang hanya bisa diperoleh dari server Alibaba** via `.so` (emulator/real device).
3. wToken user gagal (405) karena fingerprint kosong (`||`) — emulator tak menyelesaikan registrasi server.
4. **Jalur paling praktis & reliabel untuk Kopi Kenangan: ambil wToken dari device NYATA via MITM proxy.** Script `kopken_flow.py` sudah mendukung ini + punya health-check yang mendeteksi fingerprint kosong.

## 7. Referensi
- [1] 阿里App防Bot新版AliTigerTally方案浅析与算法还原1 — https://cloud.tencent.com/developer/article/1926696
- [2] cnblogs (mirror, IDA analysis) — https://www.cnblogs.com/2014asm/p/15729919.html
- [3] ibox wtoken unidbg (kode Java lengkap) — https://www.jianshu.com/p/d4c6cb0b639c
- [4] nike/SNKRS wtoken 0003 "纯算" — https://blog.csdn.net/irabbit666/article/details/128398448
- [5] AliTigerTally wtoken算法分析 (struktur 4-bagian) — https://blog.csdn.net/boshijingang/article/details/127928036
- [6] 某NFT交易平台App wtoken分析 (Frida hook _genericNt3) — https://cloud.tencent.com/developer/article/2016900
- `refrensi.txt` (chomper Python + unidbg Java examples)
