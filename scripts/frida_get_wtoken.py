#!/usr/bin/env python3
"""
frida_get_wtoken.py — Ambil wToken TigerTally dari device via Frida
===================================================================
Riset keamanan/edukasi. Jalankan di PC yang terhubung ke device Android
(rooted/emulator) dengan fra server berjalan & app Kopi Kenangan terpasang.

CARA KERJA:
  wToken = signature TigerTally, dihasilkan native libtiger_tally.so via
  Java_com_aliyun_TigerTally_common_utils_SecurityNative_gsRaw(String).
  Tidak bisa dibuat Python. Script ini melampirkan Frida ke app, meng-hook
  gsRaw (JNI export), lalu menangkap output wToken saat app memanggilnya
  (mis. saat user tekan Register/Login di app).

PENGGUNAAN:
  # 1) Pastikan frida-server jalan di device & adb terdeteksi:
  #    adb devices   ;   adb shell "su -c '/data/local/tmp/frida-server &'"
  # 2) Jalankan app Kopi Kenangan, lalu helper ini:
  python3 frida_get_wtoken.py                 # lampirkan, tunggu, simpan ke wtoken.txt
  python3 frida_get_wtoken.py --once          # tangkap 1 wtoken lalu keluar
  python3 frida_get_wtoken.py --output /path/w.txt
  python3 frida_get_wtoken.py --spawn         # spawn app otomatis (bukan attach)
  python3 frida_get_wtoken.py --device <id>   # pilih device (frida-ls-devices)

  # Setelah wtoken tersimpan, pakai di kopken_flow.py:
  python3 kopken_flow.py --flow --send --wtoken file:wtoken.txt --phone ...
  atau dari menu interaktif: pilih opsi lalu isi wtoken = "file:wtoken.txt"
"""
import sys, os, json, argparse, time

# Lazy import frida agar script tetap bisa dipakai/didokumentasikan tanpa frida terpasang.
def _import_frida():
    try:
        import frida
        return frida
    except ImportError:
        print("[!] Library 'frida' tidak terpasang. Install: pip install frida frida-tools")
        return None


# Skrip JS yang di-inject. Hook gsRaw (JNI) + fallback hook Java SecurityNative.
FRIDA_JS = r"""
'use strict';
let latest = null;

function jstringToString(env, jstr) {
    // baca Java String via JNIEnv (fallback aman)
    try {
        return env.getStringUtfChars(jstr, null).readCString();
    } catch (e) { return "<unreadable>"; }
}

// --- (A) Hook JNI export gsRaw di libtiger_tally.so ---
function hookJniGsRaw() {
    const names = [
        "Java_com_aliyun_TigerTally_common_utils_SecurityNative_gsRaw",
        "Java_com_aliyun_TigerTally_common_utils_SecurityNative_firstInitRaw",
        "Java_com_aliyun_TigerTally_common_utils_SecurityNative_secondInitRaw"
    ];
    let hooked = false;
    for (const n of names) {
        const p = Module.findExportByName("libtiger_tally.so", n);
        if (p) {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.name = n;
                    this.env = Java.vm.getEnv();
                    // gsRaw: args[0]=env, args[1]=this, args[2]=jstring input
                    try { this.inp = (args.length > 2) ? jstringToString(this.env, args[2]) : ""; }
                    catch (e) { this.inp = "?"; }
                },
                onLeave: function (ret) {
                    let out = "";
                    try { out = (ret && !ret.isNull()) ? this.env.getStringUtfChars(ret, null).readCString() : ""; }
                    catch (e) {}
                    if (this.name.indexOf("gsRaw") !== -1 && out && out.length > 20) {
                        latest = out;
                        send({ type: "wtoken", fn: this.name, input: this.inp, output: out });
                    }
                }
            });
            hooked = true;
            console.log("[+] hooked " + n);
        }
    }
    return hooked;
}

// --- (B) Fallback: hook via Java reflection (SecurityNative.gsRaw) ---
function hookJavaFallback() {
    Java.perform(function () {
        try {
            const SN = Java.use("com.aliyun.TigerTally.common.utils.SecurityNative");
            // gsRaw adalah native; coba hook overload String
            try {
                SN.gsRaw.overload('java.lang.String').implementation = function (s) {
                    const r = this.gsRaw(s);
                    if (r && r.length > 20) { latest = r; send({ type: "wtoken", fn: "SecurityNative.gsRaw", input: s, output: r }); }
                    return r;
                };
                console.log("[+] hooked SecurityNative.gsRaw(String)");
            } catch (e) { console.log("[-] gsRaw overload hook: " + e); }
        } catch (e) { console.log("[-] Java fallback: " + e); }
    });
}

rpc.exports = {
    latest: function () { return latest; }
};

setImmediate(function () {
    let ok = false;
    try { ok = hookJniGsRaw(); } catch (e) { console.log("[-] JNI hook err: " + e); }
    try { hookJavaFallback(); } catch (e) {}
    if (!ok) console.log("[!] gsRaw JNI export belum ditemukan (libtiger_tally.so belum load?). " +
                         "Hook Java fallback aktif. Picu Register/Login di app.");
    console.log("[*] Menunggu gsRaw dipanggil (lakukan Register/Login di app)...");
});
"""


def on_message(message, data):
    if message.get("type") == "send":
        p = message["payload"]
        if p.get("type") == "wtoken":
            print("\n[***] WTOKEN TERTANGKAP!")
            print("      fn    :", p["fn"])
            print("      input :", (p["input"] or "")[:60])
            print("      output:", p["output"][:70] + "..." + " (len %d)" % len(p["output"]))
            # simpan ke file default
            try:
                with open("wtoken.txt", "w") as f:
                    f.write(p["output"])
                print("      -> disimpan ke wtoken.txt")
            except Exception as e:
                print("      (gagal simpan wtoken.txt:", e, ")")
    elif message.get("type") == "error":
        print("[JS ERROR]", message.get("stack") or message.get("description"))


def main():
    ap = argparse.ArgumentParser(description="Ambil wToken TigerTally via Frida (riset).")
    ap.add_argument("--package", default="com.kopikenangan")
    ap.add_argument("--spawn", action="store_true", help="spawn app (bukan attach ke yg sedang jalan)")
    ap.add_argument("--once", action="store_true", help="tangkap 1 wtoken lalu keluar")
    ap.add_argument("--output", default="wtoken.txt", help="file simpan wtoken (default wtoken.txt)")
    ap.add_argument("--device", default=None, help="id device frida (USB jika kosong)")
    ap.add_argument("--timeout", type=int, default=0, help="timeout detik (0=selamanya)")
    args = ap.parse_args()

    frida = _import_frida()
    if frida is None:
        sys.exit(1)

    # pilih device
    try:
        dev = frida.get_device(args.device) if args.device else frida.get_usb_device(timeout=5)
    except Exception as e:
        print("[!] Tidak bisa dapat device Frida:", e)
        print("    Pastikan: device terhubung adb, frida-server berjalan di device, "
              "port di-forward (adb forward tcp:27042 tcp:27042).")
        sys.exit(1)
    print("[*] Device:", dev)

    # spawn atau attach
    try:
        if args.spawn:
            pid = dev.spawn([args.package])
            session = dev.attach(pid)
            print(f"[*] Spawned {args.package} (pid {pid})")
        else:
            session = dev.attach(args.package)
            print(f"[*] Attached to {args.package}")
    except Exception as e:
        print("[!] Gagal attach/spawn:", e)
        print("    - Pastikan app terpasang & (jika attach) sedang berjalan.")
        sys.exit(1)

    # inject
    try:
        script = session.create_script(FRIDA_JS)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        print("[!] Gagal load script:", e)
        sys.exit(1)

    if args.spawn:
        try: dev.resume(pid)
        except Exception: pass

    print(f"[*] Hook aktif. Lakukan Register/Login di app untuk memicu gsRaw.")
    print(f"[*] wToken tersimpan ke {args.output}. Ctrl+C untuk berhenti.\n")

    captured = []
    start = time.time()
    try:
        while True:
            if args.timeout and (time.time() - start) > args.timeout:
                print("[*] Timeout."); break
            # cek via RPC apakah sudah ada latest
            try:
                if script.exports_sync.latest():
                    captured.append(script.exports_sync.latest())
                    if args.once:
                        print("[*] Mode --once: wtoken tertangkap, keluar.")
                        break
            except Exception:
                pass
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Dihentikan user.")

    if captured:
        with open(args.output, "w") as f:
            f.write(captured[-1])
        print(f"\n[+] wToken terakhir disimpan ke {args.output}")
    else:
        print("\n[-] Tidak ada wToken tertangkap. Picu lagi Register/Login di app.")
    try: session.detach()
    except Exception: pass


if __name__ == "__main__":
    print("!! HANYA UNTUK RISET. Jangan akses server tanpa izin. !!\n")
    main()
