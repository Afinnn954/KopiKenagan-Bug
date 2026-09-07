#!/usr/bin/env python3
"""
kopken_flow.py — Replikasi alur Kopi Kenangan (com.kopikenangan)
================================================================
Riset keamanan / edukasi. JANGAN kirim request ke server tanpa izin.

ALUR (terverifikasi dari HAR v126.07.23):
  1. register(phone)            -> access_token sementara + kirim OTP ke HP  (auth: "**")
  2. (user terima OTP di HP)
  3. login(phone, password=OTP) -> access_token JWT resmi, is_success=true   (auth: "**")
  4. post-login requests        -> authorization: <JWT>, islogin=true, cookie acw_sc__v3
  5. check_welcome_package({})  -> eligibility welcome promo

Kriptografi (100% terverifikasi):
  clsignature = HMAC-SHA256(SECRET, plaintext_body)
  body (protected) = base64( random(3) + 0x01 + AES-256-CBC(SECRET, SECRET[:16], PKCS7(plaintext)) )
  response = plaintext JSON (tidak dienkripsi)
  wtoken   = Alibaba TigerTally -> INPUT EKSTERNAL (diambil via MITM proxy, lihat
             NO_FRIDA_WTOKEN_GUIDE.md), tidak bisa dibuat Python (lihat WT_TOKEN_ANALYSIS.md).

SECRET = "suomafsehwonhtuoyylraeniemohtfel"  (32 byte, dipakai apa adanya)
"""
import os, sys, json, hmac, hashlib, base64, argparse, subprocess
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
SECRET    = b"suomafsehwonhtuoyylraeniemohtfel"
AES_KEY   = SECRET                 # AES-256
AES_IV    = SECRET[:16]            # "suomafsehwonhtuo"
API_BASE  = "https://apps.kopikenangan.com/kk-api-kopikenangan/"

# Default nilai header (dari HAR v126.07.23/375). Ganti sesuai device uji Anda.
DEFAULT_DEVICEID     = "60a50f76e17f3dd0"
DEFAULT_APPSFLYER_ID = "1785567706719-1951644852348616957"
DEFAULT_VERSION      = "126.07.23"
DEFAULT_VERSIONCODE  = "375"
DEFAULT_SIGN_VERSION = "256"
DEFAULT_TIMEZONE     = "25200"     # Asia/Jakarta (detik)

# Endpoint yang body-nya dienkripsi (= butuh wtoken).
PROTECTED = {
    "register", "login", "thirdpartylogin", "thirdpartyaccountoptions",
    "api/customer/verifyphone", "api/customer/checkpin", "api/account/sendotp",
    "api/customer/changepin", "api/promotion/search",
    "api/giveget/creategivegetrecord", "api/giveget/claimvoucher",
}
AUTH_ANON = "**"   # marker authorization sebelum login


# =========================== KRIPTOGRAFI ===================================
def clsignature(plaintext) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return hmac.new(SECRET, plaintext, hashlib.sha256).hexdigest()

def encrypt_body(plaintext) -> str:
    if isinstance(plaintext, (dict, list)):
        plaintext = json.dumps(plaintext, separators=(",", ":"))
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    ct = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plaintext, 16))
    return base64.b64encode(os.urandom(3) + b"\x01" + ct).decode()

def decrypt_body(b64body) -> bytes:
    raw = base64.b64decode(b64body)
    assert raw[3] == 0x01, "byte versi != 0x01"
    return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(raw[4:]), 16)

def jcompact(obj) -> str:
    return "" if obj is None else (obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":")))


# =========================== SESSION =======================================
class KopKenSession:
    def __init__(self, *, deviceid=DEFAULT_DEVICEID, appsflyer_id=DEFAULT_APPSFLYER_ID,
                 version=DEFAULT_VERSION, versioncode=DEFAULT_VERSIONCODE,
                 sign_version=DEFAULT_SIGN_VERSION, timezone=DEFAULT_TIMEZONE,
                 wtoken_provider=None, verify_tls=False, verbose=True):
        self.deviceid=deviceid; self.appsflyer_id=appsflyer_id
        self.version=version; self.versioncode=versioncode
        self.sign_version=sign_version; self.timezone=timezone
        self.wtoken_provider = wtoken_provider or (lambda: "")
        self.verify_tls = verify_tls
        self.verbose = verbose
        self.http = requests.Session()
        self.access_token = None     # JWT setelah login/register
        self.is_login = False

    # --- header authorization ---
    @property
    def authorization(self):
        return self.access_token if self.access_token else AUTH_ANON

    def _headers(self, body_plain, *, protected, islogin=None, extra=None):
        if islogin is None:
            islogin = "true" if self.is_login else "false"
        wt = self.wtoken_provider()
        h = {
            "content-type": "application/json",
            "accept": "application/json",
            "appid": "kopikenangan",
            "deviceid": self.deviceid,
            "devicetype": "Android",
            "appsflyer_id": self.appsflyer_id,
            "language": "id",
            "version": self.version,
            "versioncode": self.versioncode,
            "sign_version": self.sign_version,
            "timezone": self.timezone,
            "user-agent": "Dart/3.12 (dart:io)",
            "islogin": islogin,
            "ant_support": "true",
            "gopay_v2": "true",
            "gopay_v3": "true",
            "supportsharebuy": "true",
            "authorization": self.authorization,
            "wtoken": wt,
            "clsignature": clsignature(body_plain),
        }
        if extra:
            h.update(extra)
        return h

    def request(self, method, path_query, body_obj=None, *, protected=None,
                islogin=None, extra_headers=None, dry_run=False, label=""):
        endpoint = path_query.split("?", 1)[0].lower().lstrip("/")
        if protected is None:
            protected = endpoint in PROTECTED
        body_plain = jcompact(body_obj)
        body_wire = encrypt_body(body_plain) if (protected and body_obj is not None) else body_plain
        headers = self._headers(body_plain, protected=protected, islogin=islogin, extra=extra_headers)
        url = API_BASE + path_query

        if self.verbose or dry_run:
            print(f"\n[{label or endpoint}] {method} {url}")
            print(f"  protected={protected} islogin={headers['islogin']} auth={headers['authorization'][:18]}...")
            print(f"  wtoken={headers['wtoken'][:22]}...  clsignature={headers['clsignature']}")
            print(f"  plaintext={body_plain[:90]!r}")
            print(f"  body_wire ={body_wire[:90]!r}")
        if dry_run:
            return None

        resp = self.http.request(method, url, headers=headers, data=(body_wire or None),
                                 verify=self.verify_tls, timeout=30)
        if self.verbose:
            print(f"  -> HTTP {resp.status_code} ({len(resp.content)} B)")
        # DEBUG: cetak body penuh jika bukan JSON 200 (mis. WAF challenge / 405)
        if resp.status_code != 200 or "json" not in resp.headers.get("content-type", "").lower():
            print("  --- RESPONSE BODY (debug) ---")
            print("  " + resp.text[:1500].replace("\n", "\n  "))
            print("  --- headers ---")
            for k, v in resp.headers.items():
                if k.lower() in ("content-type", "server", "x-ca-request-id", "via", "set-cookie", "x-webkit-cache"):
                    print(f"    {k}: {v[:100]}")
        return resp

    # ---------- flow helpers ----------
    def _extract_token(self, resp):
        """Ambil access_token dari response JSON & simpan."""
        if resp is None:
            return None
        try:
            data = resp.json()
        except Exception:
            return None
        tok = (data.get("data") or {}).get("access_token")
        if tok:
            self.access_token = tok
            # register/login mengindikasikan login berhasil jika is_success/otp_sent
            self.is_login = bool(((data.get("data") or {}).get("is_success"))
                                 or ((data.get("data") or {}).get("status") == "success"))
        return data

    # ======================= ALUR BISNIS ===================================
    def register(self, phone, *, marketplace_id=90001, otp_type_code=1002,
                 new_otp_options=True, new_flow=True, **kw):
        """Langkah 1: daftar -> kirim OTP & dapat access_token sementara."""
        body = {"phone": phone, "marketplace_id": marketplace_id,
                "new_otp_options": new_otp_options, "otp_type_code": otp_type_code,
                "new_flow": new_flow}
        resp = self.request("POST", "register?android_al_atb=true", body, **kw)
        return self._extract_token(resp)

    def login(self, phone, password, *, marketplace_id=90001, **kw):
        """Langkah 3: login (password = kode OTP). Dapat access_token JWT resmi."""
        body = {"grant_type": "customer", "username": phone,
                "password": password, "marketplace_id": marketplace_id}
        resp = self.request("POST", "login?android_al_atb=true", body, **kw)
        return self._extract_token(resp)

    def check_welcome_package(self, **kw):
        """Langkah 5: cek eligibility welcome promo (butuh login)."""
        return self.request("POST", "api/promotion/check_welcome_package", {}, **kw)

    def get_customer_detail(self, **kw):
        return self.request("POST", "api/customer/getCustomerDetail",
                            {"store_latitude": None, "store_longitude": None}, **kw)

    def thirdparty_account_options(self, **kw):
        return self.request("POST", "thirdpartyAccountOptions", {}, **kw)

    def promotion_registration(self, *, is_login=None, store_code=None, **kw):
        body = {"is_login": self.is_login, "store_code": store_code}
        return self.request("POST", "api/promotion/registration", body, protected=False,
                            islogin=("true" if self.is_login else "false"), **kw)


# =========================== WTOKEN PROVIDER ===============================
def make_wtoken_provider(spec):
    """spec: 'wtoken' | 'file:PATH' | 'env:VAR' | 'cmd:COMMAND'.  (NO Frida needed.)"""
    if not spec:
        return lambda: ""
    if spec.startswith("file:"):
        path = spec[5:]
        def f():
            with open(path) as fh: return fh.read().strip()
        return f
    if spec.startswith("env:"):
        var = spec[4:]
        return lambda: os.environ.get(var, "").strip()
    if spec.startswith("cmd:"):
        cmd = spec[4:]
        return lambda: subprocess.check_output(cmd, shell=True).decode().strip()
    return lambda: spec.strip()


def wtoken_check(wtoken):
    """
    Analisis kesehatan wToken (TigerTally). Format:
      0004_<sig>/<payload>==_<b64_device_fingerprint>_<appinfo>-h-<ts>-<hash>
    Mengembalikan dict {ok, fingerprint, timestamp, timestamp_str, issues}.
    Mendeteksi wToken hasil emulator dgn fingerprint KOSONG (penyebab umum HTTP 405).
    """
    import re as _re, base64 as _b64, datetime as _dt
    out = {"ok": True, "fingerprint": None, "timestamp": None, "timestamp_str": None, "issues": []}
    if not wtoken or not wtoken.startswith("0004_"):
        out["ok"] = False
        out["issues"].append("format tidak mulai '0004_' (bukan TigerTally?)")
        return out
    parts = wtoken.split("_")
    if len(parts) < 4:
        out["ok"] = False
        out["issues"].append("struktur < 4 segmen")
        return out
    dev_seg = parts[-2]
    try:
        pad = "=" * ((4 - len(dev_seg) % 4) % 4)
        out["fingerprint"] = _b64.b64decode(dev_seg + pad).decode("utf-8", "replace")
    except Exception:
        out["fingerprint"] = "<decode error>"
    m = _re.search(r"(\d{13})", parts[-1])
    if m:
        ts = int(m.group(1)); out["timestamp"] = ts
        try:
            out["timestamp_str"] = _dt.datetime.fromtimestamp(ts/1000, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            out["timestamp_str"] = "?"
    fp = out["fingerprint"] or ""
    if fp.replace("|", "").strip() == "":
        out["ok"] = False
        out["issues"].append(
            "FINGERPRINT KOSONG ('%s'). wToken kemungkinan dari emulator (unidbg/Chomper) "
            "tanpa device info -> server MENOLAK (HTTP 405/WAF). Pakai wToken device NYATA." % fp)
    return out


def print_wtoken_health(wtoken):
    if not wtoken:
        print("  [wToken] kosong - endpoint protected akan gagal."); return False
    r = wtoken_check(wtoken)
    print(f"  [wToken] fingerprint = {r['fingerprint']!r}")
    if r.get("timestamp_str"):
        print(f"  [wToken] timestamp   = {r['timestamp_str']}")
    if r["ok"]:
        print("  [wToken] SEHAT (fingerprint terisi).")
    else:
        print("  [wToken] !!! BERMASALAH:")
        for iss in r["issues"]:
            print("           -", iss)
    return r["ok"]


# =========================== SELF-TEST (vs HAR) ============================
def selftest():
    print("=" * 66 + "\n SELF-TEST terhadap data HAR\n" + "=" * 66)
    ok_all = True

    # (1) clsignature atas plaintext body (sampel HAR)
    cases = [
        ('{}', '5f7743c15e481889a818a51a13669e4ae9b893c88add4a9396d5fe7bc3d47506'),
        ('{"store_code":"CMH.SPBUCMH"}', 'a9ded57bb5e006e3e8d5152161c0fcf567c2c726efc5cc497c7da7fee3cb4133'),
        ('{"is_login":false,"store_code":null}', 'b72f629d3238e1d9fa948c8c80fd3c9365e9424b0164181bdfadc093ff024646'),
        ('{"phone":"006280000000000","marketplace_id":90001,"new_otp_options":true,"otp_type_code":1002,"new_flow":true}',
         '7a4c21ba624e07dc2dd78b11b01c1ab3274bd6dd23bfff5d66a12198832743b8'),
        ('{"grant_type":"customer","username":"006280000000000","password":"000000","marketplace_id":90001}',
         'db76c437cafe3ed00bfa68e15997b97930dbe77d2b06be62664de35b4e8b22b2'),
    ]
    print("\n[1] clsignature = HMAC-SHA256(secret, plaintext_body)")
    for pt, exp in cases:
        got = clsignature(pt); ok = got == exp; ok_all &= ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {pt[:46]!r}")

    # (2) dekripsi body terenkripsi HAR -> plaintext JSON valid
    print("\n[2] Dekripsi body AES-256-CBC (endpoint protected)")
    dec_cases = [
        ("register", "W2FoAXeWbZMcEwOB0Tl9sZAyFexxmONe5ow3mXRMkchr3pHKpjeNG/PUv635L+Mp2yQtb7WSMiWEnhfnYJ9WiOWC5JfMBqDAo3nvWVIjzaX3jyeI4tutNw/tKmTOUDPbyj/I9Qv7h/C1o+QXuL16xXTt6PM=",
         '"phone":"006280000000000"'),
        ("login", "8lWBAdjIz87of9XLPhVXLDGpEiJW2uI5fKiziFtC378hKCTLA41+1Y0srVNBJtIL0r3WcBWwuq8hcGiKXiVIVO+ATUNJE/SJac87FfRA/98JckgqetHC1fC6yxcAf/pYNgHl+m1RQzgIe2dcSjbeZVaXKlc=",
         '"grant_type":"customer"'),
        ("thirdpartyAccountOptions", "mEwmATImh0p3Azg98mbLR7MtRF4=", "{}"),
    ]
    for label, b64, expect_substr in dec_cases:
        try:
            pt = decrypt_body(b64).decode(); ok = expect_substr in pt; ok_all &= ok
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:24} -> {pt[:50]!r}")
        except Exception as e:
            ok_all = False; print(f"  [FAIL] {label}: {e}")

    # (3) AES round-trip (encrypt lalu decrypt = plaintext asli)
    print("\n[3] AES round-trip")
    for msg in [b'{"a":1}', b'{}', b'{"phone":"0062"}']:
        ct = encrypt_body(msg); rt = decrypt_body(ct); ok = rt == msg; ok_all &= ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {msg!r}")

    print("\n  => " + ("SEMUA PASS — algoritma & alur siap." if ok_all else "ADA YANG GAGAL."))
    return ok_all


# =========================== MENU INTERAKTIF ===============================
def _ask(prompt, default=None):
    s = input(prompt).strip()
    return s if s else (default if default is not None else "")

def _print_resp(resp):
    if resp is None:
        print("  (tidak ada response / dry-run)"); return
    print(f"  HTTP {resp.status_code}  ({len(resp.content)} B)")
    ct = resp.headers.get("content-type", "")
    if "json" in ct:
        try: print(json.dumps(resp.json(), indent=2, ensure_ascii=False)[:1200])
        except Exception: print(resp.text[:800])
    else:
        print("  body:", resp.text[:400])

def interactive_menu():
    """Menu default (user non-CLI friendly). State disimpan di session aktif."""
    print("=" * 48)
    print("  KOPKEN FLOW TEST  (interactive)  [riset keamanan]")
    print("=" * 48)
    print("Catatan: endpoint protected BUTUH wToken (TigerTally).")
    print("         Ambil wToken via MITM proxy (lihat NO_FRIDA_WTOKEN_GUIDE.md),")
    print("         lalu tempel / 'file:wtoken.txt' / 'env:WTOKEN'.")
    print("         Mode simulasi (tidak kirim) aktif sampai Anda setuju kirim.\n")

    # setup awal
    wtoken_spec = _ask("wToken (tempel / 'file:wtoken.txt' / 'env:WTOKEN' / kosong): ")
    deviceid    = _ask(f"DeviceId [{DEFAULT_DEVICEID}]: ", DEFAULT_DEVICEID)
    appsflyer   = _ask(f"Appsflyer_id [{DEFAULT_APPSFLYER_ID}]: ", DEFAULT_APPSFLYER_ID)
    phone       = _ask("Nomor HP default (0062...): ")

    sess = KopKenSession(deviceid=deviceid, appsflyer_id=appsflyer,
                         wtoken_provider=make_wtoken_provider(wtoken_spec), verbose=True)
    do_send = False
    print_wtoken_health(sess.wtoken_provider())

    while True:
        print("\n" + "-" * 48)
        print(" 1. Register (kirim OTP)")
        print(" 2. Login (pakai OTP)")
        print(" 3. Check Welcome Package")
        print(" 4. Flow Lengkap (register->login->check_welcome)")
        print(" 5. getCustomerDetail")
        print(" 6. Dekripsi body terenkripsi")
        print(" 7. Selftest (verifikasi formula)")
        print(" 8. Ganti wToken / phone / device")
        print("10. Cek kesehatan wToken (deteksi fingerprint kosong)")
        print(f" 9. Toggle mode kirim  [sekarang: {'KIRIM KE SERVER' if do_send else 'SIMULASI (dry-run)'}]")
        print(" 0. Keluar")
        try:
            ch = _ask("Pilih [0-9]: ")
        except (EOFError, KeyboardInterrupt):
            print(); break
        if ch == "0" or ch == "":
            break
        wt_ok = bool(sess.wtoken_provider())

        try:
            if ch == "1":
                p = _ask(f"Nomor HP [{phone}]: ", phone) or phone; phone = p
                if not wt_ok and do_send: print("  [!] wToken kosong — isi dulu (menu 8)."); continue
                _print_resp(sess.register(p, dry_run=not do_send))
            elif ch == "2":
                p = _ask(f"Nomor HP [{phone}]: ", phone) or phone; phone = p
                otp = _ask("Kode OTP (6 digit): ")
                if not wt_ok and do_send: print("  [!] wToken kosong — isi dulu (menu 8)."); continue
                _print_resp(sess.login(p, otp, dry_run=not do_send))
                if do_send and sess.access_token:
                    print("  access_token:", sess.access_token[:50], "...")
            elif ch == "3":
                if not wt_ok and do_send: print("  [!] wToken kosong — isi dulu (menu 8)."); continue
                _print_resp(sess.check_welcome_package(dry_run=not do_send))
            elif ch == "4":
                p = _ask(f"Nomor HP [{phone}]: ", phone) or phone; phone = p
                otp = _ask("Kode OTP (6 digit): ")
                if not wt_ok and do_send: print("  [!] wToken kosong — isi dulu (menu 8)."); continue
                print("\n--- Register ---"); _print_resp(sess.register(p, dry_run=not do_send))
                print("\n--- Login ---");    _print_resp(sess.login(p, otp, dry_run=not do_send))
                print("\n--- Check Welcome ---"); _print_resp(sess.check_welcome_package(dry_run=not do_send))
            elif ch == "5":
                _print_resp(sess.get_customer_detail(dry_run=not do_send))
            elif ch == "6":
                b = _ask("Body terenkripsi (base64): ")
                try: print("  plaintext:", decrypt_body(b).decode())
                except Exception as e: print("  gagal:", e)
            elif ch == "7":
                selftest()
            elif ch == "8":
                wtoken_spec = _ask("wToken baru: ", wtoken_spec)
                phone = _ask(f"Nomor HP [{phone}]: ", phone) or phone
                sess.wtoken_provider = make_wtoken_provider(wtoken_spec)
                sess.deviceid = _ask(f"DeviceId [{sess.deviceid}]: ", sess.deviceid) or sess.deviceid
                print("  diperbarui.")
            elif ch == "10":
                print_wtoken_health(sess.wtoken_provider())
            elif ch == "9":
                do_send = not do_send
                print(f"  mode sekarang: {'KIRIM KE SERVER' if do_send else 'SIMULASI'}")
                if do_send:
                    print("  !!! PERHATIAN: request NYATA akan dikirim ke server Kopi Kenangan.")
                    conf = _ask("  Ketik 'YA-SAYA-PASTI' untuk konfirmasi: ")
                    if conf.strip().upper() != "YA-SAYA-PASTI":
                        do_send = False; print("  dibatalkan, kembali ke SIMULASI.")
            else:
                print("  pilihan tidak dikenal.")
        except requests.RequestException as e:
            print("  [network error]", e)
        except Exception as e:
            print("  [error]", e)
    print("Bye.")


# =========================== CLI ===========================================
def main():
    ap = argparse.ArgumentParser(description="Kopi Kenangan flow (riset keamanan).")
    ap.add_argument("--menu", action="store_true", help="paksa masuk menu interaktif")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="bangun request tanpa kirim")
    ap.add_argument("--flow", action="store_true", help="jalankan alur penuh")
    ap.add_argument("--send", action="store_true", help="(dengan --flow) benar2 kirim ke server")
    ap.add_argument("--step", choices=["register","login","check_welcome","customer_detail"],
                    help="jalankan satu langkah")
    ap.add_argument("--wtoken", default="", help="wtoken | file:PATH | env:VAR | cmd:COMMAND")
    ap.add_argument("--deviceid", default=DEFAULT_DEVICEID)
    ap.add_argument("--appsflyer-id", default=DEFAULT_APPSFLYER_ID)
    ap.add_argument("--phone", default="006281200000000", help="nomor HP uji (format 0062...)")
    ap.add_argument("--otp", default="", help="kode OTP (password login)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    # Tanpa perintah relevan -> menu interaktif (default, user friendly)
    has_cli = args.flow or args.step or args.menu
    if not has_cli:
        interactive_menu()
        return

    dry = args.dry_run
    send = args.send
    actually_send = send and not dry
    if args.flow and not actually_send and not dry:
        print("[i] --flow tanpa --send -> default ke --dry-run (simulasi). "
              "Tambahkan --send untuk kirim sungguhan.")
        dry = True

    sess = KopKenSession(deviceid=args.deviceid, appsflyer_id=args.appsflyer_id,
                         wtoken_provider=make_wtoken_provider(args.wtoken),
                         verbose=True)
    sess.verbose = True

    def _guard_wtoken():
        wt = sess.wtoken_provider()
        if not wt and not dry:
            print("[!] wtoken kosong. Protected endpoint butuh wtoken TigerTally dari device.")
            print("    Lewati kirim, atau beri --wtoken / --dry-run.")
            return False
        if wt:
            healthy = print_wtoken_health(wt)
            if not healthy and actually_send:
                print("[!] wToken bermasalah (fingerprint kosong/expired). Permintaan nyata")
                print("    hampir pasti ditolak (HTTP 405/WAF). Ambil wToken dari device NYATA")
                print("    via MITM proxy (lihat NO_FRIDA_WTOKEN_GUIDE.md). Kirim dibatalkan.")
                return False
        return True

    if args.step == "register" or (args.flow):
        if not _guard_wtoken(): return
        print("\n######## LANGKAH 1: REGISTER (kirim OTP) ########")
        sess.register(args.phone, dry_run=dry)

    if args.step == "login" or (args.flow):
        otp = args.otp or "000000"
        print("\n######## LANGKAH 3: LOGIN (password=OTP) ########")
        if not _guard_wtoken(): return
        r = sess.login(args.phone, otp, dry_run=dry)
        if actually_send and r is not None:
            print("  access_token:", (sess.access_token or "")[:60], "...")

    if args.step in ("customer_detail",) or (args.flow and actually_send):
        print("\n######## LANGKAH 4: getCustomerDetail (auth JWT) ########")
        sess.get_customer_detail(dry_run=dry)

    if args.step == "check_welcome" or (args.flow):
        print("\n######## LANGKAH 5: check_welcome_package ########")
        if not _guard_wtoken(): return
        r = sess.check_welcome_package(dry_run=dry)
        if actually_send and r is not None:
            try: print("  ", json.dumps(r.json(), ensure_ascii=False)[:200])
            except Exception: print("  ", r.text[:200])

    if not (args.flow or args.step):
        ap.print_help()
        print("\nContoh:\n"
              "  python3 kopken_flow.py --selftest\n"
              "  python3 kopken_flow.py --flow --dry-run\n"
              "  python3 kopken_flow.py --step register --dry-run --phone 0062812XXXXXXXX\n"
              "  python3 kopken_flow.py --flow --send --wtoken 0004_XXXX --phone 0062812XXXXXXXX --otp 123456")


if __name__ == "__main__":
    print("!! HANYA UNTUK RISET KEAMANAN/EDUKASI. Jangan akses server tanpa izin. !!\n")
    main()
