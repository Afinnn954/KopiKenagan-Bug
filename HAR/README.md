# HAR (HTTP Archive) — Catatan

File HAR asli (`kopken.json`, 3.8 MB, 76 entri) **tidak disertakan** di repo karena berisi data pribadi peneliti:
- Nomor HP asli (plaintext & di dalam body terenkripsi)
- Kode OTP / password sesi
- JWT `access_token`
- wToken + device fingerprint
- Cookie sesi (`acw_sc__v3`)

## Alternatif yang tersedia di repo
- `evidence/kk_requests_sanitized.json` — ekstrak 24 request API Kopi Kenangan dari HAR
  (method, path+query, clsignature, body) **tanpa** data pribadi; body register/login
  berbentuk ciphertext AES-256-CBC (belum didekripsi).
- Dokumentasi mendetail ada di `docs/REPORT.md`, `docs/FLOW_REPORT.md`,
  `docs/REQUEST_MATCH_TEST.md`.

## Jika butuh HAR lengkap
Rekam ulang sendiri via MITM proxy (lihat `docs/NO_FRIDA_WTOKEN_GUIDE.md`), lalu
simpan secara **privat** — jangan di-commit ke repo publik.
