# Riset Forum/Blog China — wToken TigerTally

> Total **19 sumber** dari **8+ platform** (CSDN, Tencent Cloud, cnblogs, Jianshu, 91fans, kanxue看雪, Programmer Sought, Aliyun docs, GitHub).

## Tabel sumber

| # | Platform | URL (ringkas) | Versi wToken | Inti temuan |
|---|---|---|---|---|
| 1 | CSDN | blog.csdn.net/irabbit666/.../128398448 | **0003** | Nike/SNKRS 纯算 (device gen+register+sign, closed-source); 16 cipher + SHA256 modifikasi |
| 2 | CSDN | blog.csdn.net/Qiled/.../124674233 | 0003 | unidbg flow `_genericNt2→1→3`, for64Bit |
| 3 | CSDN | blog.csdn.net/m0_67925133/.../124679366 | (ibox) | unidbg call sequence, AndServer RPC |
| 4 | CSDN | blog.csdn.net/boshijingang/.../127928036 | (iOS) | **wToken = version+timestamp+signature+device_info** (4 bagian) |
| 5 | CSDN | blog.csdn.net/weixin_42484892/.../124698333 | (ibox) | "授人以渔": black-box via AndServer RPC paling reliabel; 反射+hook randomize device |
| 6 | CSDN | blog.csdn.net/qq_41823971/.../124674233 | (ibox) | unidbg + kode |
| 7 | CSDN | blog.csdn.net/m0_70787272/.../124700044 | (NFT) | unidbg setup |
| 8 | **Tencent** | cloud.tencent.com/developer/article/1926696 | (0001/2) | **PALING LENGKAP**: flow, anti-detect (xp/frida/magisk/hook/root/debug/multi), **pb() POST server utk fingerprint**, HMAC multi-ronde + UUID, kode restorasi §6.1 |
| 9 | **cnblogs** | cnblogs.com/2014asm/p/15729919.html | (0001/2) | mirror IDA; **kode restorasi**: AES-CBC key=`24e96202f2d6fe64` iv=`632870a7427e3bdc`, MD5(`7dfd964a-...`)→aeskey, iv2/3=`55b4dc20eaf2a88a` |
| 10 | Jianshu | jianshu.com/p/d4c6cb0b639c | (ibox) | **Kode Java unidbg LENGKAP** + mock JNI (Build/PackageManager/SharedPreferences/pb) |
| 11 | Jianshu | jianshu.com/p/fbc9abbe758d | (NFT) | Frida hook `_genericNt3(a,b)` |
| 12 | 91fans/Tencent | cloud.tencent.com/developer/article/2016900 | (NFT) | Frida RPC pola |
| 13 | Programmer Sought | programmersought.com/article/885111461920 | (ibox) | EN version, unidbg flow |
| 14 | **kanxue看雪** | bbs.kanxue.com/article-23478.htm | (顶象 DXRisk) | device fingerprint: kumpulkan → upload ke server risk → **token dikembalikan server** (sama pola dgn TigerTally) |
| 15 | **kanxue看雪** | bbs.kanxue.com/thread-273759 | (大厂指纹) | device fingerprint: Java+Native+popen; IPC proxy hook detection; mock tak cukup |
| 16 | **Aliyun docs** | help.aliyun.com/zh/waf/.../integrate-anti-bot-sdk-ios | (iOS) | API resmi: `initialize:(appkey)` + `vmpSign:(data)` |
| 17 | GitHub | chenhu/ibox_wtoken_unidbg (refrensi.txt) | (ibox) | Java: `callFunc3` → `_genericNt3`, mock tt_ak `^1652122636405^86400` |
| 18 | GitHub | sledgeh4w/chomper (refrensi.txt) | (iOS, Python) | Chomper: ObjC `AliTigerTally.vmpSign:` |
| 19 | GitHub | zhkl0228/unidbg | — | Android/iOS native emulator (tool dasar) |

## Insight kunci lintas-sumber

1. **Flow universal** (semua sumber): `_genericNt2`(decrypt appkey) → `_genericNt1`(collect device + **POST ke server Alibaba pb()** → fingerprint token) → `_genericNt3`(sign).
2. **Fingerprint dari server** (sumber 8, 9, 14): device fingerprint token dikembalikan server, bukan dihitung lokal. Pola sama dgn 顶象/DXRisk (sumber 14).
3. **纯算 0003 closed-source** (sumber 1): satu-satunya restorasi pure-algorithm publik disebut, tapi kode tak dibagikan. Versi 0004 **belum ada publikasi**.
4. **Pendekatan dominan = black-box unidbg/AndServer-RPC** (sumber 5, 8, 10): karena VMP obfuscation terlalu berat untuk 纯算. Real device (AndServer) paling stabil.
5. **Anti-detection** (sumber 8, 15): emulator/proxy/root/hook(Frida/Xposed)/debug/multi-open + IPC proxy hook detection → mock Build tidak cukup (sumber 15).
6. **Restorasi algoritma 2021** (sumber 9): AES-CBC konstanta spesifik versi (key `24e96202f2d6fe64` dll) — **versi 0004 berbeda**, konstanta diganti.
