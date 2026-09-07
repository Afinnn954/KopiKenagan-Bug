#!/usr/bin/env python3
"""
kopken_request.py — Kopi Kenangan (com.kopikenangan) request builder
====================================================================
Riset keamanan / edukasi. JANGAN kirim request ke server tanpa izin.

Rumus yang SUDAH TERVERIFIKASI 100% (via HAR + dekripsi):
  * clsignature  = HMAC-SHA256( SECRET , plaintext_body )            [hex]
  * body (protected endpoints) =
        base64( os.urandom(3) + b'\\x01'                              # [rnd3][ver=01]
                + AES-256-CBC( KEY=SECRET , IV=SECRET[:16] , PKCS7(plaintext) ) )
  * SECRET (dipakai APA ADANYA, bukan dibalik):
        "suomafsehwonhtuoyylraeniemohtfel"   (32 byte)
  * response body: plaintext JSON (TIDAK dienkripsi).
  * wtoken: Alibaba TigerTally — input eksternal (dari device asli). Tidak bisa dibuat Python.

Endpoint yang BODY-nya dienkripsi (= endpoint "protected", butuh wtoken):
  register, login, thirdpartyAccountOptions, api/customer/verifyPhone,
  api/customer/checkPin, api/account/sendOtp, api/customer/changePin,
  api/promotion/search, api/giveGet/createGiveGetRecord, api/giveGet/claimVoucher,
  thirdpartyLogin
Endpoint lain mengirim body plaintext JSON (clsignature tetap atas plaintext).
"""
import os, sys, json, hmac, hashlib, base64, argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

# ---------------------------------------------------------------------------
# Konstanta (terverifikasi)
# ---------------------------------------------------------------------------
SECRET  = b"suomafsehwonhtuoyylraeniemohtfel"   # 32 byte — kunci HMAC sekaligus AES-256
AES_KEY = SECRET                                 # AES-256 key
AES_IV  = SECRET[:16]                            # "suomafsehwonhtuo" — IV CBC
API_BASE = "https://apps.kopikenangan.com/kk-api-kopikenangan/"

PROTECTED = {                                    # endpoint yg body-nya dienkripsi
    "register", "login", "thirdpartylogin", "thirdpartyaccountoptions",
    "api/customer/verifyphone", "api/customer/checkpin", "api/account/sendotp",
    "api/customer/changepin", "api/promotion/search",
    "api/giveget/creategivegetrecord", "api/giveget/claimvoucher",
}


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def clsignature(plaintext):
    """HMAC-SHA256(SECRET, plaintext_body) -> hex64."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return hmac.new(SECRET, plaintext, hashlib.sha256).hexdigest()


def encrypt_body(plaintext):
    """AES-256-CBC + PKCS7, format [rnd(3)][0x01][ct], lalu base64."""
    if isinstance(plaintext, (dict, list)):
        plaintext = json.dumps(plaintext, separators=(",", ":"))
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    ct = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(os.urandom(3) + b"\x01" + ct).decode()


def decrypt_body(body_b64):
    """Kebalikan dari encrypt_body. Lewati 4-byte prefix lalu AES-256-CBC."""
    raw = base64.b64decode(body_b64)
    return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(raw[4:]), AES.block_size)


def build_headers(wtoken, deviceid, appsflyer_id, clsig, *,
                  version="126.07.23", versioncode="375",
                  sign_version="256", islogin="false", cookie="",
                  extra=None):
    """Susun header persis seperti app (format dari HAR)."""
    h = {
        "content-type":   "application/json",
        "accept":         "application/json",
        "appid":          "kopikenangan",
        "deviceid":       deviceid,
        "devicetype":     "Android",
        "appsflyer_id":   appsflyer_id,
        "language":       "id",
        "version":        version,
        "versioncode":    versioncode,
        "sign_version":   sign_version,
        "timezone":       "25200",            # Asia/Jakarta UTC+7 (detik)
        "user-agent":     "Dart/3.12 (dart:io)",
        "islogin":        islogin,
        "ant_support":    "true",
        "gopay_v2":       "true",
        "gopay_v3":       "true",
        "supportsharebuy":"true",
        "clsignature":    clsig,
        "wtoken":         wtoken,
    }
    if cookie:
        h["cookie"] = cookie
    if extra:
        h.update(extra)
    return h


# ---------------------------------------------------------------------------
# Request helper
# ---------------------------------------------------------------------------
def kk_request(method, path, body_obj, *, wtoken, deviceid, appsflyer_id,
               encrypt=None, verify_tls=False, **hdr_extra):
    """
    Kirim request ke KK API.
      method      : "POST"/"GET"
      path        : path setelah API_BASE, boleh ada query (mis. "register?android_al_atb=true")
      body_obj    : dict/list/str plaintext. Untuk GET bisa None.
      encrypt     : True/False/None. None => auto (enkripsi bila endpoint protected).
    """
    endpoint = path.split("?", 1)[0].lower().lstrip("/")
    if encrypt is None:
        encrypt = endpoint in PROTECTED

    # body plaintext (JSON compact, sesuai app)
    if body_obj is None:
        plaintext = ""
        data = None
    else:
        plaintext = body_obj if isinstance(body_obj, str) else json.dumps(body_obj, separators=(",", ":"))
        data = encrypt_body(plaintext) if encrypt else plaintext

    clsig = clsignature(plaintext)
    headers = build_headers(wtoken, deviceid, appsflyer_id, clsig, **hdr_extra)
    url = API_BASE + path

    print(f"[*] {method} {url}")
    print(f"    encrypt_body={encrypt}  plaintext={plaintext[:80]!r}")
    print(f"    clsignature={clsig}")
    print(f"    body_sent  ={(data or '')[:80]!r}")

    resp = requests.request(method, url, headers=headers, data=data, verify=verify_tls, timeout=30)
    print(f"[*] HTTP {resp.status_code}  ({len(resp.content)} bytes)")
    return resp


# ---------------------------------------------------------------------------
# Demo: register
# ---------------------------------------------------------------------------
def demo_register(wtoken, deviceid, appsflyer_id):
    """Contoh register (endpoint protected: body dienkripsi)."""
    body = {
        "phone": "006281200000000",        # ganti nomor uji milik sendiri
        "marketplace_id": 90001,
        "new_otp_options": True,
        "otp_type_code": 1002,
        "new_flow": True,
    }
    return kk_request("POST", "register?android_al_atb=true", body,
                      wtoken=wtoken, deviceid=deviceid, appsflyer_id=appsflyer_id)


# ---------------------------------------------------------------------------
# Self-test: rekonstruksi clsignature & dekripsi dari sampel HAR
# ---------------------------------------------------------------------------
def selftest():
    print("=" * 64 + "\n SELF-TEST (verifikasi rumus terhadap sampel)\n" + "=" * 64)
    samples = [
        # (plaintext, expected_clsignature)
        ('{}', '5f7743c15e481889a818a51a13669e4ae9b893c88add4a9396d5fe7bc3d47506'),
        ('{"store_code":"CMH.SPBUCMH"}',
         'a9ded57bb5e006e3e8d5152161c0fcf567c2c726efc5cc497c7da7fee3cb4133'),
        ('{"is_login":false,"store_code":null}',
         'b72f629d3238e1d9fa948c8c80fd3c9365e9424b0164181bdfadc093ff024646'),
        ('{"phone":"006280000000000","marketplace_id":90001,"new_otp_options":true,"otp_type_code":1002,"new_flow":true}',
         '2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1'),
    ]
    allok = True
    for pt, exp in samples:
        got = clsignature(pt)
        ok = got == exp
        allok &= ok
        print(f"  [{'OK' if ok else 'FAIL'}] HMAC({pt[:40]!r}...) = {got}")
    # AES round-trip
    for msg in [b'{}', b'{"phone":"0062"}']:
        ct = encrypt_body(msg)
        pt = decrypt_body(ct)
        ok = pt == msg
        allok &= ok
        print(f"  [{'OK' if ok else 'FAIL'}] AES round-trip {msg!r} -> {ct[:24]}... -> {pt!r}")
    print("\n  => " + ("SEMUA OK — rumus benar" if allok else "ADA YANG GAGAL"))
    return allok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Kopi Kenangan request builder (riset).")
    ap.add_argument("--selftest", action="store_true", help="verifikasi rumus tanpa kirim request")
    ap.add_argument("--decrypt", metavar="BODY_B64", help="dekripsi body AES-CBC")
    ap.add_argument("--clsig", metavar="PLAINTEXT", help="hitung clsignature dari plaintext")
    ap.add_argument("--endpoint", default="register?android_al_atb=true", help="endpoint KK")
    ap.add_argument("--wtoken", default="", help="wToken TigerTally (WAJIB utk protected endpoint)")
    ap.add_argument("--deviceid", default="0000000000000000", help="DeviceId")
    ap.add_argument("--appsflyer_id", default="0-0", help="appsflyer_id")
    ap.add_argument("--phone", default="006281200000000", help="nomor uji")
    ap.add_argument("--dry-run", action="store_true", help="bangun request tanpa benar2 kirim")
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if args.decrypt:
        print(decrypt_body(args.decrypt)); return
    if args.clsig:
        print(clsignature(args.clsig)); return

    body = {"phone": args.phone, "marketplace_id": 90001,
            "new_otp_options": True, "otp_type_code": 1002, "new_flow": True}
    if args.dry_run:
        pt = json.dumps(body, separators=(",", ":"))
        print("plaintext :", pt)
        print("clsignature:", clsignature(pt))
        print("encrypted :", encrypt_body(pt))
        return

    if not args.wtoken:
        sys.exit("[!] wToken wajib untuk protected endpoint. Dapatkan dari device "
                 "(Frida hook gsRaw) lalu: --wtoken 0004_....")
    r = kk_request("POST", args.endpoint, body,
                   wtoken=args.wtoken, deviceid=args.deviceid, appsflyer_id=args.appsflyer_id)
    try:
        print(json.dumps(r.json(), indent=2, ensure_ascii=False))
    except Exception:
        print(r.text[:500])


if __name__ == "__main__":
    print("!! HANYA UNTUK RISET KEAMANAN/EDUKASI. Jangan akses server tanpa izin. !!\n")
    main()
