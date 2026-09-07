# Hasil Pengujian Script Python

## 1. Environment
- Python 3.13.14, pycryptodome (terpasang), requests 2.33.0
- Java OpenJDK 11, Maven 3.9.9
- `libtiger_tally.so`: ELF64 ARM aarch64, NDK r21e, stripped, 4.3 MB

## 2. Self-test `kopken_flow.py --selftest`
```
[1] clsignature = HMAC-SHA256(secret, plaintext_body)
  [PASS] '{}'
  [PASS] '{"store_code":"CMH.SPBUCMH"}'
  [PASS] '{"is_login":false,"store_code":null}'
  [PASS] '{"phone":"00628XXXXXXXXX",...}'          (register)
  [PASS] '{"grant_type":"customer",...}'            (login)
[2] Dekripsi body AES-256-CBC
  [PASS] register                 -> '{"phone":"00628XXXXXXXXX",...}'
  [PASS] login                    -> '{"grant_type":"customer",...}'
  [PASS] thirdpartyAccountOptions -> '{}'
[3] AES round-trip
  [PASS] b'{"a":1}' / b'{}' / b'{"phone":"0062"}'
=> SEMUA PASS
```

## 3. Dry-run vs HAR (register sukses)
Mengambil register sukses dari HAR (status 200, response ada `access_token`):
- deviceid     = `60a50f76e17f3dd0`
- appsflyer_id = `1785567706719-1951644852348616957`
- wtoken       = `0004_9FBC213E9A3589EE...` (fingerprint `9581d31b...` terisi)
- HAR clsignature = `2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1`

Build via script `KopKenSession` dengan deviceid/wtoken HAR →
```
script clsignature : 2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1
HAR    clsignature : 2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1
MATCH: True
```
✅ **Kriptografi (clsignature + AES body) script 100% benar** dan identik dgn app asli.

## 4. Health-check wToken
| wToken | fingerprint | timestamp | Diagnosis |
|---|---|---|---|
| HAR (sukses) | `9581d31b17855677171286244ec302\|...` | 2026-08-01 | ✅ SEHAT |
| User (405) | **`\|\|` (KOSONG)** | 2026-08-23 10:12 | ❌ BERMASALAH — emulator tanpa device info, server menolak |

✅ Health-check (`wtoken_check()`) **benar mendeteksi** penyebab 405 (fingerprint kosong).

## 5. Kesimpulan pengujian
- **Selain wToken**, semua kriptografi Kopi Kenangan sudah benar & terverifikasi vs HAR.
- wToken tidak bisa dibuat Python; yang user buat (via emulator) punya fingerprint kosong → ditolak.
- Script `kopken_flow.py` siap pakai: tinggal beri wToken valid (dari device nyata MITM).
