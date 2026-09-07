# LAPORAN RISET MENDALAM: wToken TigerTally (Alibaba) untuk Kopi Kenangan

> Riset keamanan/edukasi. Tujuan: menentukan apakah `wToken` bisa dibuat Python murni, atau solusi terbaik memperoleh wToken valid. Tidak ada request ke server produksi tanpa izin.

---

## 1. Ringkasan Eksekutif

**Jawaban utama: `wToken` versi 0004 TIDAK bisa dibuat Python murni** — dan blokernya **bukan "device generation"**, melainkan **fingerprint token yang hanya bisa diperoleh dari server Alibaba** via `.so` (emulator/device nyata).

| Pendekatan | Kelayakan | Catatan |
|---|---|---|
| Python murni (crypto saja) | ❌ Tidak | Algoritma VMP-obfuscated; hanya versi **lama 0003** pernah di-纯算 (closed-source). 0004 belum publik. |
| unidbg/Chomper + selesaikan `pb()` | ⚠️ Sulit | Harus POST registrasi ke server Alibaba; anti-emulator bisa menolak → fingerprint kosong → 405. |
| Cloud phone farm (real hardware) | ✅ Stabil | Real device di cloud → fingerprint asli → wToken valid. Lewati anti-emulator. |
| Capture device nyata (MITM) | ✅ Termudah | Untuk volume rendah/riset. |
| Replay wToken | ⚠️ Sangat terbatas | Per-request unik + time-bound; window singkat. |

**Rekomendasi:** untuk riset/low-volume → **MITM proxy dari device nyata** (`kopken_flow.py` + health-check). Untuk high-volume/skalabel → **cloud phone farm** (real hardware). Python murni untuk `wToken` **bukan opsi realistis**.

---

## 2. Metodologi

**Kata kunci (≈20):** `wToken TigerTally Python`, `AliTigerTally 纯算`, `wToken 0004 algorithm`, `TigerTally unidbg`, `libtiger_tally.so reverse`, `Nike SNKRS wToken python`, `ibox wtoken python`, `TigerTally device fingerprint`, `Alibaba anti-bot wToken generate`, `tt_ak TigerTally`, `_genericNt3`, `pb() 设备指纹`, `wToken replay`, `cloud phone farm`, dll.

**Platform dijelajahi (7+):** CSDN (5 artikel), Tencent Cloud, cnblogs, Jianshu, 91fans/奋飞安全, Programmer Sought, GitHub (zhkl0228/unidbg, chenhu/ibox_wtoken_unidbg, chomper), device farm sites (devicefarm.io, pcloudy), RE Stack Exchange, Reddit.

**Diverifikasi ulang:** struktur wToken dari HAR Kopi Kenangan (24 sampel), decoding segmen fingerprint, perbandingan wToken user (405) vs HAR (sukses).

---

## 3. Temuan Utama (sumber relevan)

| # | Sumber | Penulis/Tanggal | Ringkasan |
|---|---|---|---|
| S1 | [Tencent Cloud — AliTigerTally浅析与算法还原](https://cloud.tencent.com/developer/article/1926696) | 我是小三, 2021-12 | **Paling lengkap**: flow `_genericNt2→1→3`, HMAC multi-ronde + UUID `b5c0d0a4-...`, AES(key dari MD5), **POST ke server untuk fingerprint**, anti-detection (xp/frida/magisk/hook/root/debug/multi-open). |
| S2 | [cnblogs — mirror S1 dgn IDA](https://www.cnblogs.com/2014asm/p/15729919.html) | 2014asm, 2021-12 | Detail IDA: `Dec_RiskString`, `RegNative`, alamat fungsi. |
| S3 | [Jianshu — ibox wtoken unidbg kode](https://www.jianshu.com/p/d4c6cb0b639c) | 北方蜘蛛, 2022-05 | **Kode Java unidbg lengkap**: mock JNI (Build/PackageManager/SharedPreferences), call `_genericNt1→2→3`, mock `pb()` hardcoded. |
| S4 | [CSDN — nike/SNKRS 纯算 0003](https://blog.csdn.net/irabbit666/article/details/128398448) | irabbit666, 2022-12 | **纯算 (pure algorithm)** utk versi 0003: device generation + device registration + signature — **closed-source**. |
| S5 | [CSDN — AliTigerTally struktur 4-bagian](https://blog.csdn.net/boshijingang/article/details/127928036) | boshijingang, 2022-11 | wToken = version + timestamp + signature + device_info; payload terdekripsi = device/system/network. |
| S6 | [91fans/Tencent — NFT wtoken Frida hook](https://cloud.tencent.com/developer/article/2016900) | 奋飞, 2022-06 | Frida hook `_genericNt3(a,b)` untuk capture input/output. Pola RPC. |
| S7 | `refrensi.txt` (lokal) | chomper + ibox_wtoken_unidbg | Chomper (Python, iOS) + unidbg (Java, Android) examples. |
| S8 | [CSDN — unidbg-ibox 授人以渔](https://blog.csdn.net/weixin_42484892/article/details/124698333) | 2022-05 | 16 cipher + SHA256 modifikasi; **AndServer RPC** di real device paling reliabel. |

---

## 4. Analisis Teknis

### 4.1 Struktur wToken (4 segmen, terverifikasi dari HAR)
```
0004_<sig_hex 96char>/<payload_b64 ~640>==_<devfp_b64>_<appinfo>-h-<ts_ms>-<md5hash>
```
- `0004` = versi format
- `sig_hex` = signature (berubah per-request)
- `payload_b64` = data device terenkripsi (device/system/network)
- `devfp_b64` = **fingerprint token dari server Alibaba** (mis. `9581d31117855677301363762ee583|...`)
- `appinfo-h-ts-hash` = `e6a858e8bc7bb0f9` (app-derived) + timestamp ms + MD5

### 4.2 Algoritma internal (dari S1)
1. **`_genericNt2(appkey)`** — Base64+AES decrypt appkey → beberapa string kunci.
2. **`_genericNt1`** — kumpulkan device info via double-reflection (JNI `forName`/`getDeclaredMethod`) → encrypt tiap field (VM_Entrance, 90% logic) → combine+compress → AES(key=MD5(...)) → **POST ke server Alibaba** (`pb()`/`postnet`) → terima **fingerprint token** → cache (`tt_ak`).
3. **`_genericNt3(request_body)`** — sign:
   - `msg = request_body + SERVER_FINGERPRINT + device_risk + CRC + random`
   - `hmac1 = HMAC(msg)`
   - `hmac2 = HMAC(decrypted_appkey_data + hmac1 + UUID "b5c0d0a4-4763-44e8-baa6-dfca9a66efdb")`
   - result = `random + hmac2`, lalu compress/AES/base64 → segmen payload.

### 4.3 Perbedaan 0003 vs 0004
- **0003** (Nike/SNKRS, ~2022-2024): berhasil di-纯算 oleh tim khusus (S4) tapi **closed-source**. Bisa generate device sintetis + registrasi + sign tanpa `.so`.
- **0004** (Kopi Kenangan, ~2025-2026): lebih baru, anti-emulator lebih kuat, **belum ada publikasi 纯算**. Setiap upaya publik memakai unidbg (black-box).

### 4.4 Kendala teknis utama
- **VMP obfuscation**: 1692 fungsi nama-acak, 16 cipher, SHA256 modifikasi (S8), VM_Entrance dispatcher.
- **Anti-detection**: emulator/proxy/root/hook(Frida/Xposed)/debug/multi-open (S1).
- **Server dependency**: fingerprint `9581d311...` datang dari POST ke server Alibaba — tidak bisa dihitung lokal.
- **Time-bound**: signature + payload berubah per-request (24/24 unik di HAR).

---

## 5. Uji Coba & Hasil

### 5.1 Uji wToken user (Python murni, dari emulator)
- wToken: fingerprint `||` **KOSONG** → **HTTP 405** (2.6 KB, WAF challenge).
- **Penyebab** (terbukti): emulator tidak menyelesaikan registrasi server `pb()` → fingerprint kosong → server menolak.
- `kopken_flow.py` health-check kini **mendeteksi** kondisi ini otomatis.

### 5.2 Uji kesesuaian script vs HAR (dry-run)
- clsignature (HMAC-SHA256) + body AES-CBC: **MATCH 4/4** vs HAR (register, login, check_welcome, query_menu).
- → kriptografi **selain wToken** sudah 100% benar. Tinggal wToken valid.

### 5.3 Tidak ada request produksi dikirim — semua verifikasi via dry-run & data HAR.

---

## 6. Kelayakan Pendekatan (tabel detail)

| Pendekatan | Mungkin? | Kesulitan | Stabilitas | Volume | Catatan |
|---|---|---|---|---|---|
| **Python murni (纯算)** 0004 | ❌ | — | — | — | Algoritma tidak publik; S4 hanya 0003 closed. |
| **unidbg black-box** | ⚠️ | Tinggi | Rendah¹ | Sedang | Butuh Java; `pb()` ke server; anti-emulator (catatan ¹). |
| **Chomper (Python)** | ⚠️ | Tinggi | Rendah¹ | Sedang | Untuk binary iOS; tidak langsung utk Android. |
| **Frida/objection RPC real device** | ✅ | Sedang | Tinggi | Sedang | Real device; fingerprint valid. |
| **AndServer RPC (app di real device)** | ✅ | Sedang | Tinggi | Tinggi | Bikin app kecil, HTTP endpoint wToken (S8). |
| **Cloud phone farm** | ✅ | Rendah | Tinggi | Tinggi | Real hardware cloud (devicefarm.io); fingerprint asli. |
| **MITM capture device nyata** | ✅ | Rendah | Tinggi² | Rendah | Termudah; catatan ²: time-bound. |
| **Replay wToken** | ⚠️ | — | Sangat rendah | — | Per-request unik + time-bound; window singkat. |

¹ Anti-emulator: server Alibaba bisa menolak registrasi device emulator → fingerprint kosong/invalid → 405 (persis yang dialami user).
² wToken time-bound → ambil segar sebelum pakai.

---

## 7. Rekomendasi (langkah konkret)

### Untuk RISET / volume rendah (paling mudah)
1. Siapkan 1 device Android nyata + MITM proxy (`mitmproxy`).
2. Buka app Kopi Kenangan, capture `wtoken` + `deviceid` + `appsflyer_id` dari request yang sama (lihat `NO_FRIDA_WTOKEN_GUIDE.md`).
3. Pakai `kopken_flow.py` (menu opsi 10 untuk health-check dulu).
- ✅ Script kriptografi sudah terbukti benar (clsignature + AES).

### Untuk VOLUME TINGGI / skalabel (paling stabil)
- **Cloud phone farm** (devicefarm.io / pcloudy): real Android hardware di cloud, tiap device IMEI/MAC/fingerprint asli → wToken valid. Lewati anti-emulator sepenuhnya. Automasi via Appium/adb + MITM capture.
- ATAU **AndServer RPC**: deploy app kecil di farm device nyata yang expose HTTP endpoint `_genericNt3` (pola S8).

### Pendekatan EMULATOR (jika tetap mau coba, risiko 405 tinggi)
1. unidbg (Java): load `libtiger_tally.so` + APK Kopi Kenangan, mock Build realistis (MODEL/BRAND/DEVICE/RELEASE + Android-ID).
2. **JANGAN mock `pb()` kosong** — biarkan `.so` POST ke server Alibaba untuk dapat fingerprint.
3. Jika server tolak (anti-emulator) → fingerprint tetap kosong → 405. Solusi: kombinasi dgn cloud device.

### ❌ Tidak direkomendasikan
- Python murni untuk `wToken` 0004 (waktu invest sangat besar, hasil tidak dijamin; algoritma tertutup).
- Replay wToken lama (akan ditolak).

---

## 8. Referensi (URL lengkap)
1. https://cloud.tencent.com/developer/article/1926696 — AliTigerTally浅析与算法还原1 (Tencent, 我是小三)
2. https://www.cnblogs.com/2014asm/p/15729919.html — mirror IDA analysis
3. https://www.jianshu.com/p/d4c6cb0b639c — ibox wtoken unidbg (kode Java)
4. https://blog.csdn.net/irabbit666/article/details/128398448 — nike/SNKRS 纯算 0003
5. https://blog.csdn.net/boshijingang/article/details/127928036 — struktur wToken 4-bagian
6. https://cloud.tencent.com/developer/article/2016900 — NFT wtoken Frida hook
7. https://blog.csdn.net/weixin_42484892/article/details/124698333 — unidbg-ibox 授人以渔
8. https://blog.csdn.net/Qiled/article/details/124674233 — ibox wtoken unidbg
9. https://www.programmersought.com/article/885111461920/ — ibox wtoken algorithm (EN)
10. https://github.com/zhkl0228/unidbg — Android/iOS native emulator
11. https://devicefarm.io/ — real Android cloud phone farm
12. `~/kopken_analysis/refrensi.txt` — chomper Python + ibox unidbg Java

---

## 9. Catatan Etika & Batasan
- **Hanya untuk riset keamanan/edukasi dengan izin**, di sistem/akun milik sendiri.
- Reverse-engineering TigerTally untuk produksi (bot/akun massal/promo abuse/scraping) **melanggar ToS Alibaba & Kopi Kenangan**, berisiko sengketa hukum.
- Cloud phone farm & AndServer RPC utk bypass anti-bot skala besar dapat dianggap penyalahgunaan — gunakan dgn otorisasi.
- **Tidak ada request ke server produksi** dikirim dalam riset ini; semua verifikasi via dry-run & data HAR.
- wToken mengandung fingerprint device pribadi — jangan dibagikan.
