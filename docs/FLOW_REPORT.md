# LAPORAN ALUR (FLOW) — Kopi Kenangan

**Script:** `kopken_flow.py` (self-test & dry-run 100% PASS)
**Sumber:** HAR `kopken.json` (76 entri, versi 126.07.23/375)
**Tujuan:** riset keamanan/edukasi — replikasi alur register → OTP → login → check promo.

> ⚠️ Jangan akses server Kopi Kenangan tanpa izin. `wtoken` (TigerTally) adalah penghalang sah yang tidak bisa dipalsukan tanpa device asli.

---

## 1. Diagram Alur (teks)

```
                         [SEMUA request butuh: clsignature + wtoken]
                                    |
   ┌────────────────────────────────┴────────────────────────────────┐
   │  PRE-LOGIN  (authorization: "**", islogin: false)                │
   └──────────────────────────────────────────────────────────────────┘
        │
        ▼
 (1) POST /register?android_al_atb=true      [body DIENKRIPSI]
     body = {"phone":"0062...","marketplace_id":90001,
             "new_otp_options":true,"otp_type_code":1002,"new_flow":true}
     ──► 200 {"data":{"access_token":"<JWT sementara>",
                       "otp_sent":true,"status_text":"Phone exists"...}}
        │   (OTP dikirim ke nomor HP)
        ▼
 (2) *** USER MENERIMA OTP DI HP (6 digit) ***     [di luar aplikasi]
        │
        ▼
 (3) POST /login?android_al_atb=true         [body DIENKRIPSI]
     body = {"grant_type":"customer","username":"0062...",
             "password":"<OTP 6 digit>","marketplace_id":90001}
     ──► 200 {"data":{"access_token":"<JWT resmi>","is_success":true,
                       "customer_id":4880911,"status":"success"}}
        │   access_token disimpan; is_login = true
        ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  POST-LOGIN  (authorization: "<JWT>", islogin: true,             │
   │               cookie: acw_sc__v3=...  [dari WAF, auto via Session])│
   └──────────────────────────────────────────────────────────────────┘
        │
        ├─► POST /api/customer/getCustomerDetail   → profil customer
        ├─► POST /api/promotion/registration       → status promo
        ├─► POST /widget/query_page_widgets        → konten home
        └─► POST /api/promotion/check_welcome_package  body={}
                ──► 200 {"data":null,"error_code":-1,
                          "msg":"Anda belum bisa mendapatkan welcome package,
                                 karena sudah pernah melakukan transaksi"}
```

**Catatan OTP:** di HAR tidak ada endpoint `sendOtp` eksplisit — `register` langsung memicu pengiriman OTP (`otp_sent:true`). Lalu `login` memakai OTP tsb sebagai `password`. (Jalur captcha Alibaba `cloudauth-device`/`captcha-open` terjadi paralel sebagai verifikasi anti-bot — bagian dari TigerTally/WAF.)

---

## 2. Tabel Endpoint (dari HAR, terverifikasi)

| Langkah | Method | Path | Body plaintext | Protected? | Header khusus | Response penting |
|---|---|---|---|---|---|---|
| 1 | POST | `register?android_al_atb=true` | `{phone, marketplace_id:90001, new_otp_options:true, otp_type_code:1002, new_flow:true}` | ✅ enkripsi | auth=`**`, islogin=`false` | `access_token`, `otp_sent:true`, `status_text` |
| 3 | POST | `login?android_al_atb=true` | `{grant_type:"customer", username:phone, password:<OTP>, marketplace_id:90001}` | ✅ enkripsi | auth=`**`, islogin=`false` | `access_token` JWT, `is_success`, `customer_id` |
| — | POST | `thirdpartyAccountOptions` | `{}` | ✅ enkripsi | islogin=`false` | daftar opsi login 3rd-party |
| — | POST | `api/promotion/registration` | `{is_login:<bool>, store_code:<code\|null>}` | ❌ plaintext | islogin sesuai status | status registrasi promo |
| 4 | POST | `api/customer/getCustomerDetail` | `{store_latitude:null, store_longitude:null}` | ❌ plaintext | auth=`<JWT>`, islogin=`true` | profil customer lengkap |
| 5 | POST | `api/promotion/check_welcome_package` | `{}` | ❌ plaintext | auth=`<JWT>`, islogin=`true` | eligibility welcome promo |
| — | POST | `widget/get_page_layout`, `widget/query_page_widgets` | `{page_id, is_payment_promo_v2, ...}` | ❌ plaintext | — | layout/konten UI |
| — | POST | `api/store/get_store_by_code` | `{store_code, latitude, longitude}` | ❌ plaintext | — | info outlet |
| — | POST | `api/cart/query_cart` | `{outlet_id, promotion_codes, form...}` | ❌ plaintext | auth=`<JWT>` | isi keranjang |
| — | GET | `config/app_skin` | (kosong) | ❌ | — | skin/konfigurasi |

**Body selalu JSON compact** (`json.dumps(..., separators=(",",":"))`). clsignature selalu dihitung atas plaintext body ini.

---

## 3. Header Wajib (semua request KK API)

```
content-type: application/json      accept: application/json
appid: kopikenangan                 deviceid: <16 hex>
devicetype: Android                 appsflyer_id: <id>
language: id                        timezone: 25200
version: 126.07.23                  versioncode: 375
sign_version: 256                   user-agent: Dart/3.12 (dart:io)
islogin: true|false                 ant_support: true
gopay_v2: true   gopay_v3: true     supportsharebuy: true
authorization: ** | <JWT>           # "**" pra-login, JWT setelah login
wtoken: 0004_<hex TigerTally>       # WAJIB, dari device (Frida)
clsignature: <HMAC-SHA256(secret, plaintext_body)>
cookie: acw_sc__v3=...              # auto via requests.Session (dari WAF)
```

---

## 4. Cara Pakai `kopken_flow.py`

```bash
# A) Verifikasi algoritma vs HAR (tanpa kirim):
python3 kopken_flow.py --selftest

# B) Simulasi alur penuh (bangun request, TIDAK kirim):
python3 kopken_flow.py --flow --dry-run --phone 0062812XXXXXXXX --otp 123456

# C) Satu langkah saja (simulasi):
python3 kopken_flow.py --step register --dry-run --phone 0062812XXXXXXXX

# D) Kirim sungguhan (HANYA jika punya izin + wtoken dari device):
#    wtoken bisa: string langsung | file:PATH | cmd:'perintah frida'
python3 kopken_flow.py --flow --send \
    --wtoken "0004_ABCDEF..." \
    --phone 0062812XXXXXXXX --otp 123456
```

**wtoken** diambil dari device asli via Frida (skrip `frida_kopikenangan.js` hook `gsRaw`). Tanpa wtoken valid, endpoint protected akan ditolak/dichallenge WAF Alibaba.

### API Python
```python
from kopken_flow import KopKenSession, make_wtoken_provider
sess = KopKenSession(wtoken_provider=make_wtoken_provider("0004_XXXX"))
sess.register("0062812XXXXXXXX")                 # kirim OTP
otp = input("OTP: ")                             # dari SMS
sess.login("0062812XXXXXXXX", otp)               # dapat JWT
print(sess.check_welcome_package().json())       # pakai JWT otomatis
```

---

## 5. Kriptografi (ringkas, 100% terverifikasi)

- `clsignature = HMAC-SHA256("suomafsehwonhtuoyylraeniemohtfel", plaintext_body)`
- Body protected = `base64( random(3) + 0x01 + AES-256-CBC(KEY=secret, IV=secret[:16], PKCS7(plaintext)) )`
- Response = plaintext JSON (tidak dienkripsi)
- `wtoken` = TigerTally native (`gsRaw`) — tidak bisa dibuat Python.

---

## 6. Catatan & Batasan

- **WAF Alibaba**: di HAR, request register/login yang diulang mendapat challenge HTML (`aliyun_waf_aa`). Request pertama dengan wtoken valid berhasil. Script tidak mereplikasi challenge WAF/captcha — itu tanggung jawab TigerTally (`wtoken`) di device.
- **`authorization`** header = JWT mentah (tanpa prefix `Bearer`). Pra-login = literal `"**"`.
- **`sign_version`** berubah antar versi app (HAR 126.07.23 = `256`; APK 126.08.13 = `512`). Bisa di-set via `KopKenSession(sign_version=...)`.
- GET dengan body kosong (mis. `config/app_skin`) punya clsignature yang bukan `HMAC(secret,"")` — kemungkinan pakai input lain; tidak krusial untuk alur register/login/promo.

---

## 7. File Deliverable (`~/kopken_analysis/`)

| File | Isi |
|---|---|
| **`kopken_flow.py`** | Script alur lengkap (KopKenSession + register/login/check_welcome + CLI). Self-test PASS. |
| **`FLOW_REPORT.md`** | Laporan ini |
| `kopken_request.py` | Script dasar (clsignature/AES/request) |
| `FINAL_REPORT.md` | Laporan dekripsi kriptografi |
| `frida_kopikenangan.js` | Frida hook (gsRaw/clsignature) |
| `kopken.json` | HAR asli |
| `kk_requests.json` | 24 request KK terekstrak |

Semua verifikasi dilakukan terhadap data HAR — **tidak ada request ke server produksi** yang dikirim dalam analisis ini.
