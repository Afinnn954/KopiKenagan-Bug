#!/usr/bin/env python3
"""
PoC - Reverse Engineering Kopi Kenangan (com.kopikenangan v126.08.13)
=====================================================================
Tujuan: riset keamanan / edukasi. JANGAN kirim request ke server tanpa izin.

TEMUAN (dari libapp.so via blutter + disassembly manual capstone):
  * wToken      = Alibaba TigerTally signature (bukan RSA). app_key diekstrak.
  * clsignature = HMAC-SHA256. Secret DITEMUKAN: "lefthomeinearlyyouthnowhesfamous"
                  (disimpan terbalik "suomafsehwonhtuoyylraeniemohtfel" di pool).
                  Fungsi sign @ libapp+0x463fa8. sign_version header = 512.
  * body req/resp = AES-GCM (nonce 12 + ciphertext + tag 16). AES engine class KKb.

Catatan:
  - Message HMAC clsignature mengandung nilai per-request (timestamp/nonce) yang
    tidak ada di sampel → urutan field eksak dikonfirmasi via Frida (hook 0x463fa8).
  - Kunci AES-GCM BUKAN konstanta statis → diekstrak via Frida (hook KKb/javax.crypto).
"""

import base64
import hashlib
import hmac

# ---------------------------------------------------------------------------
# Konstanta yang BERHASIL diekstrak dari libapp.so
# ---------------------------------------------------------------------------
APP_ID       = "kopikenangan"
SIGN_VERSION = "512"                       # header sign_version = 0x200
API_BASE     = "https://apps.kopikenangan.com/kk-api-kopikenangan/"

# TigerTally app_key  ([pp+0x28638]) -- dipakai di method channel tigerTallyInit
TIGERTALLY_APPKEY = (
    "XSA0N3Mpig995urXtzaCfIujI8f-ERcHgo65FDUPGQz6ojzV0O4StRtu0Awok0FUPDj_"
    "uAXl0-E7YnuIh72-IctLQce_iE9oiPL51qYq8SweKyYv66JWQSztbtVca84LtH7jVriQn"
    "YINUVKEyGcPXICaKgydDUM5M_lJkM7MAqk="
)

# === clsignature secret (DITEMUKAN) ===
# [pp+0xc6f8] String "suomafsehwonhtuoyylraeniemohtfel" (disimpan terbalik)
SECRET_STORED   = "suomafsehwonhtuoyylraeniemohtfel"
SECRET_REVERSED = "lefthomeinearlyyouthnowhesfamous"   # nilai efektif (kode membalik)
CLSIG_SECRET    = SECRET_REVERSED.encode()             # kunci HMAC-SHA256

# AES key body: butuh Frida (hook KKb). Kosongkan sampai didapat.
AES_KEY_HEX = ""

# 11 endpoint terproteksi yang memicu signing (clsignature + wToken)
PROTECTED_ENDPOINTS = [
    "register", "login", "api/customer/verifyPhone", "api/customer/checkPin",
    "api/account/sendOtp", "api/customer/changePin", "api/promotion/search",
    "api/giveGet/createGiveGetRecord", "api/giveGet/claimVoucher",
    "thirdpartyLogin", "thirdpartyAccountOptions",
]


# ===========================================================================
# 1) clsignature = HMAC-SHA256(secret, message)
# ===========================================================================
def build_clsignature(message: bytes, secret: bytes = CLSIG_SECRET) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def brute_clsignature(method, path, body_b64, deviceid, target_sig, secret=CLSIG_SECRET):
    """Coba banyak kemungkinan field message (secret sudah diketahui).
    Akan MISS untuk sampel tanpa timestamp — itu mengonfirmasi message butuh
    nilai per-request. Hook Frida 0x463fa8 untuk dapatkan message eksak."""
    body_raw = base64.b64decode(body_b64)
    mp = (method + path).encode()
    dev, app = deviceid.encode(), APP_ID.encode()
    cands = {
        "hmac(body_raw)":            hmac.new(secret, body_raw, hashlib.sha256).hexdigest(),
        "hmac(body_b64)":            hmac.new(secret, body_b64.encode(), hashlib.sha256).hexdigest(),
        "hmac(mp+body_raw)":         hmac.new(secret, mp + body_raw, hashlib.sha256).hexdigest(),
        "hmp(mp+body_raw+dev+app)":  hmac.new(secret, mp + body_raw + dev + app, hashlib.sha256).hexdigest(),
        "hmac(dev+app+mp+body_raw)": hmac.new(secret, dev + app + mp + body_raw, hashlib.sha256).hexdigest(),
        "hmac(body_raw+dev+app)":    hmac.new(secret, body_raw + dev + app, hashlib.sha256).hexdigest(),
    }
    found = None
    for n, v in cands.items():
        ok = (v == target_sig)
        print(f"  [{'OK' if ok else '  '}] {n:30s} = {v}")
        if ok:
            found = n
    msg = ("COCOK: " + found) if found else "tidak cocok (sampel tanpa timestamp) - hook Frida 0x463fa8"
    print(f"  >> {msg}")
    return found


# ===========================================================================
# 2) AES-GCM  (body request/response)   — butuh AES_KEY via Frida
# ===========================================================================
def aes_gcm_decrypt(body_b64, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    raw = base64.b64decode(body_b64)
    nonce, tag, ct = raw[:12], raw[-16:], raw[12:-16]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)

def aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce=None) -> str:
    from Crypto.Cipher import AES
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(plaintext)
    return base64.b64encode(c.nonce + ct + tag).decode()

def demo_body_structure():
    body = ("azWaATyM/lKyWDm8nRpZEIe0fmMLsahE3SWGUuVqoFxKiu1SvosazUYFaJZ4/pRe"
            "79nANKUbEEthR1P0UhaqUQpxEf8q1YaSmasqTFWw5qDh3oIfTOxa7cv/GB2Z3d3"
            "KYONYC0cWGVghvCN96aAW4DI+c/o=")
    raw = base64.b64decode(body)
    print(f"[body] decoded={len(raw)}B  nonce(12)={raw[:12].hex()}  tag(16)={raw[-16:].hex()}")
    print(f"       ct={len(raw)-28}B  -> AES-GCM (116%16={len(raw)%16}!=0, CBC/ECB ditolak)")


# ===========================================================================
# 3) wToken (Alibaba TigerTally) - alur konseptual
# ===========================================================================
def wtoken_flow():
    print(f"[wToken] app_key TigerTally = {TIGERTALLY_APPKEY[:48]}...")
    print("[wToken] format = <108 hex char (54B)><base64 body ~496B>")
    print("[wToken] generator = libtiger_tally.so :: gsRaw(String)  (black-box)")


if __name__ == "__main__":
    print("=" * 68)
    print(" KOPI KENANGAN RE PoC | AppId=%r sign_version=%s" % (APP_ID, SIGN_VERSION))
    print("=" * 68)
    print(f"\n[0] clsignature SECRET (found): {SECRET_REVERSED!r}")
    print(f"    (stored reversed in pool:    {SECRET_STORED!r})")
    print(f"    algo: HMAC-SHA256, fn @ libapp+0x463fa8\n")

    print("[1] Body structure (AES-GCM) ".ljust(60, "-"))
    demo_body_structure()

    print("\n[2] clsignature HMAC-SHA256 brute-force (secret known) ".ljust(60, "-"))
    brute_clsignature(
        method="POST",
        path="/kk-api-kopikenangan/register?android_al_atb=true",
        body_b64=("azWaATyM/lKyWDm8nRpZEIe0fmMLsahE3SWGUuVqoFxKiu1SvosazUYFaJZ4/pRe"
                  "79nANKUbEEthR1P0UhaqUQpxEf8q1YaSmasqTFWw5qDh3oIfTOxa7cv/GB2Z3d3"
                  "KYONYC0cWGVghvCN96aAW4DI+c/o="),
        deviceid="5689c72eecf67c03",
        target_sig="2282f0aa5e329a52ca51ee6407565df2b21afa4317c66b2f2c3a0f7a3d9768f1",
    )

    print("\n[3] wToken (TigerTally) flow ".ljust(60, "-"))
    wtoken_flow()
    print("\n[done] Lihat REPORT.md + frida_kopikenangan.js untuk hook presisi.")
