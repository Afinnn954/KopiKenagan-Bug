/*============================================================================
 * Frida hook script — Kopi Kenangan (com.kopikenangan v126.08.13)
 * Tujuan: riset keamanan/edukasi. Jalankan di device milik sendiri.
 *
 * Temuan statis (dari libapp.so via blutter + disassembly manual):
 *   - clsignature : HMAC-SHA256  (secret = "suomafsehwonhtuoyylraeniemohtfel",
 *                                 disimpan terbalik; reversed = "lefthomeinearlyyouthnowhesfamous")
 *   - sign fn     : libapp+0x463fa8  (input x1 = message Dart-String; ret x0 = hex sig)
 *   - SHA256 core : libapp+0xdb67b4 ; SHA256 init(H0): libapp+0xd1bb00
 *   - wToken fn   : libapp+0xeae718  (→ method channel tigerTallySign)
 *   - AES engine  : class KKb (Mjo); GCM/CTR modes _Rha/_Qha/_Nha (Jin)
 *   - TigerTally  : libtiger_tally.so  JNI  Java_com_aliyun_TigerTally_common_utils_SecurityNative_gsRaw
 *
 * Helper getDartString/getTaggedObjectValue berasal dari blutter_frida.js
 * (salin blok helper tsb dari blutter_out/blutter_frida.js ke sini, atau
 *  require/gabungkan). Di bawah versi ringkas untuk membaca OneByteString.
 *==========================================================================*/

const SECRET_STORED = "suomafsehwonhtuoyylraeniemohtfel";
const SECRET_REVERSED = SECRET_STORED.split('').reverse().join(''); // lefthomeinearlyyouthnowhesfamous
console.log("[*] clsignature secret (as stored):", SECRET_STORED);
console.log("[*] clsignature secret (reversed) :", SECRET_REVERSED);

// ---- minimal Dart OneByteString reader (untuk hasil cepat) ---------------
// Dart AOT: OneByteString length di [ptr+0x7]>>1, data mulai ptr+0x8 (compressed ptr).
// Gunakan helper lengkap dari blutter_frida.js (getTaggedObjectValue) untuk akurasi.
function tryReadDartString(ptrOrTagged, base) {
    try {
        const p = (base && ptr(ptrOrTagged).compare(ptr(base)) < 0)
                   ? base.add(ptrOrTagged.toInt32()) : ptr(ptrOrTagged);
        const len = (p.add(7).readU8()) >>> 1;
        if (len > 0 && len < 4096) return p.add(8).readUtf8String(len);
    } catch (e) {}
    return null;
}

// ===========================================================================
function hookClSignature(libapp) {
    // 0x463fa8: input x1 = message; return x0 = signature hex
    const fn = libapp.add(0x463fa8);
    Interceptor.attach(fn, {
        onEnter: function (args) {
            this.msg = tryReadDartString(this.context.x1, null);
            console.log("\n[ClSignature] >>> message to sign:");
            console.log("   " + this.msg);
        },
        onLeave: function (ret) {
            const sig = tryReadDartString(ret, null);
            console.log("[ClSignature] <<< signature: " + sig);
        }
    });
    console.log("[+] hooked ClSignature @ libapp+0x463fa8");

    // Also hook the HMAC/inner function 0x4642ec (uses secret) to confirm key
    Interceptor.attach(libapp.add(0x4642ec), {
        onEnter: function () {
            console.log("[ClSignature] (HMAC init/inner 0x4642ec) x1=" + this.context.x1);
        }
    });
}

// ===========================================================================
function hookAES(libapp) {
    // The AES engine + GCM modes are in Mjo/Jin. The most reliable spot to grab
    // the AES KEY is the AES engine init / processBlock. Hook the SHA256-area
    // is not relevant; instead, scan for the AES init by name via blutter classes.
    //
    // Strategy A (recommended): hook Dart's typed-data write when key is set.
    // Strategy B: attach to the GCM/CTR mode constructors. Their class ids:
    //   _Rha (GCM?) id from blutter, _Qha, _Nha  -> addresses via blutter_frida.js Classes[]
    //
    // Generic: log every 16/32-byte Uint8List allocation near crypto is noisy;
    // instead, hook the known AES engine "processBlock" by searching libapp for
    // the function that references the runtime-built AES tables (_Sgk offset 0x1618).
    //
    // >>> SIMPLEST RELIABLE HOOK: the AES-GCM nonce is 12 bytes & random.
    //     Hook the pointycastle GCM 'processBlock' by attaching to libapp+<addr>.
    //     To get the exact addr, run:  grep "processBlock\|class _Rha" asm/Jin.dart
    //     and use blutter_frida.js to resolve, OR use the Java side (see below).

    // --- Java-side fallback: many Flutter crypto plugins call javax.crypto ---
    Java.perform(function () {
        try {
            const Cipher = Java.use("javax.crypto.Cipher");
            const SecretKeySpec = Java.use("javax.crypto.SecretKeySpec");
            SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
                console.log("[AES][Java] SecretKeySpec(" + algo + ") key(hex) = " + bytesToHex(key) + "  len=" + key.length);
                return this.$init(key, algo);
            };
            Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
                console.log("[AES][Java] Cipher.init mode=" + mode + " algo=" + key.getAlgorithm());
                return this.init(mode, key);
            };
            console.log("[+] hooked javax.crypto (SecretKeySpec/Cipher.init) — jika AES lewat Java");
        } catch (e) { console.log("[-] javax.crypto hook skipped:", e); }
    });
}

// ===========================================================================
function hookTigerTally() {
    // wToken = gsRaw(String) native export. EXACT & reliable.
    const sym = "Java_com_aliyun_TigerTally_common_utils_SecurityNative_gsRaw";
    const fn = Module.findExportByName("libtiger_tally.so", sym);
    if (!fn) { console.log("[-] gsRaw export not found (libtiger_tally.so not loaded yet?)"); return; }
    Interceptor.attach(fn, {
        onEnter: function (args) {
            // JNI: args[0]=env, args[1]=this, args[2]=jstring input
            try { this.inp = Java.vm.getEnv().getStringUtfChars(args[2], null).readCString(); }
            catch (e) { this.inp = "?"; }
            console.log("\n[TigerTally] gsRaw input  = " + this.inp);
        },
        onLeave: function (ret) {
            try {
                const s = Java.vm.getEnv().getStringUtfChars(ret, null).readCString();
                console.log("[TigerTally] gsRaw output = " + (s.length > 120 ? s.slice(0, 60) + "..." + s.slice(-40) + " (len " + s.length + ")" : s));
            } catch (e) { console.log("[TigerTally] gsRaw output (non-string ret)"); }
        }
    });
    console.log("[+] hooked TigerTally gsRaw @ libtiger_tally.so");

    // Also hook the Dart caller 0xeae718 (logs the wtoken slot)
    const libapp = Module.findBaseAddress("libapp.so");
    if (libapp) Interceptor.attach(libapp.add(0xeae718), {
        onLeave: function (ret) { console.log("[TigerTally] Dart caller 0xeae718 returned (wToken candidate)"); }
    });
}

// ===========================================================================
function bytesToHex(b) { return Array.from(b).map(x => ("0" + (x & 0xff).toString(16)).slice(-2)).join(""); }

// ===========================================================================
function waitForLibapp() {
    const i = setInterval(function () {
        const libapp = Module.findBaseAddress("libapp.so");
        if (libapp) {
            clearInterval(i);
            console.log("[*] libapp.so base = " + libapp);
            hookClSignature(libapp);
            hookAES(libapp);
            hookTigerTally();
            console.log("\n[*] All hooks installed. Lakukan register/login di app dan amati output.\n");
        }
    }, 200);
}
waitForLibapp();
