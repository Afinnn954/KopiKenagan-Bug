# UJI KESESUAIAN REQUEST vs HAR (dry-run, tanpa kirim)

Memvalidasi bahwa `kopken_flow.py` mereplikasi request HAR secara presisi. **Dijalankan tanpa mengirim ke server** — hanya membandingkan output fungsi crypto script dengan data HAR asli.

## Metode
Untuk beberapa entri HAR, plaintext body diberikan ke fungsi script (`clsignature` + `encrypt_body`), lalu dibandingkan dengan `clsignature` & body di HAR.

## Hasil: SEMUA MATCH ✅

| # | Endpoint | Jenjang | plaintext (dari HAR) | clsignature | body |
|---|---|---|---|---|---|
| 1 | `api/promotion/check_welcome_package` | plaintext | `{}` | `5f7743c15e481889...` **MATCH** | `{}` **MATCH (exact)** |
| 2 | `api/product/query_menu_promotion_product` | plaintext | `{"store_code":"CMH.SPBUCMH"}` | `a9ded57bb5e006e3...` **MATCH** | exact **MATCH** |
| 3 | `register?android_al_atb=true` | **terenkripsi** | `{"phone":"00628XXXXXXXXX","marketplace_id":90001,"new_otp_options":true,"otp_type_code":1002,"new_flow":true}` | `2282f0aa5e329a52...` **MATCH** | format `byte[3]=0x01` + `ct[4:]` **MATCH** |
| 4 | `login?android_al_atb=true` | **terenkripsi** | `{"grant_type":"customer","username":"00628XXXXXXXXX","password":"XXXXXX","marketplace_id":90001}` | `da2d63e10c4baebb...` **MATCH** | format `byte[3]=0x01` + `ct[4:]` **MATCH** |

### Catatan teknis
- **clsignature** = HMAC-SHA256(secret, plaintext_body). Cocok **byte-for-byte** di keempat kasus (plaintext maupun terenkripsi — clsignature selalu dihitung atas plaintext).
- **Body terenkripsi**: byte `[0:3]` = random, `byte[3]` = `0x01` (versi), `byte[4:]` = AES-256-CBC ciphertext. Karena byte random berbeda tiap request, body full tidak identik — **tetapi `byte[3]=0x01` cocok dan `ct[4:]` identik** (plaintext sama → ciphertext deterministik dengan IV tetap). Inilah buji valid: script menghasilkan ciphertext yang sama untuk plaintext yang sama.
- Header lain (appid, deviceid, sign_version, dll.) sesuai HAR (lihat `FLOW_REPORT.md` §3).

## Reproduksi uji
```bash
cd ~/kopken_analysis
python3 -c "
import json, base64, kopken_flow as k
print('check_welcome:', k.clsignature('{}'))
print('register     :', k.clsignature('{\"phone\":\"00628XXXXXXXXX\",\"marketplace_id\":90001,\"new_otp_options\":true,\"otp_type_code\":1002,\"new_flow\":true}'))
"
# Harus cetak:
#   check_welcome: 5f7743c15e481889a818a51a13669e4ae9b893c88add4a9396d5fe7bc3d47506
#   register     : 2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1
```

## Kesimpulan
Script **benar dan siap**. Saat Anda punya `wToken` segar (via MITM proxy), tinggal kirim — header `clsignature`, enkripsi body, dan format sudah terbukti identik dengan app asli.
