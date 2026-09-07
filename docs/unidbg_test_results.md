# Hasil Pengujian Implementasi unidbg

## 1. Yang dilakukan
1. `pip install pycryptodome capstone` (siapkan Python deps).
2. `sudo apt-get install -y maven` → Maven 3.9.9 terpasang.
3. `git clone https://github.com/zhkl0228/unidbg.git` (success, 1609 file).
4. Tulis `KopiKenTigerTally.java` (adaptasi example ibox dgn app_key Kopi Kenangan `XSA0N3Mpig...`) di `unidbg-android/src/test/java/com/aliyun/`.
5. `mvn -pl unidbg-api,unidbg-android -am compile`.

## 2. Hasil: BUILD GAGAL (Java version incompatibility)
```
ERROR .../AbstractARMDebugger.java:[1419,9] reference to Module is ambiguous
  both class com.github.unidbg.Module in com.github.unidbg
   and class java.lang.Module in java.lang match
```
**Akar masalah:** unidbg (HEAD) ditulis untuk **Java 8**. Environment sandbox = **OpenJDK 11**, di mana `java.lang.Module` ada → bentrok dgn `com.github.unidbg.Module`. Bisa diatasi dgn install JDK 8, tapi build ulang berat & tetap tidak menyelesaikan bloker utama (§3).

## 3. Bloker utama (meski build sukses): `pb()` registrasi server
Dari kode `KopiKenTigerTally.java` + analisis `refrensi.txt` (ibox example) + sumber China:
- `_genericNt1` memanggil `com/aliyun/TigerTally/A->pb(String,[B)String` → **network POST ke server Alibaba** utk daftar device & dapat fingerprint token.
- Di example ibox (Jianshu/refrensi.txt), `pb()` **di-mock hardcoded** (`wS8O4RYy...`), sehingga fingerprint token itu **bukan dari server asli** — itu sebabnya wToken ibox hanya lolos utk app ibox sendiri, bukan cross-app valid.
- Untuk Kopi Kenangan: mock `pb()` kosong → fingerprint `||` → **405** (persis yang user alami).
- Mau tak mau, registrasi server HARUS dilakukan → tapi:
  - Permintaan registrasi itu sendiri ditandatangani `.so` (algoritma obfuscated).
  - Anti-emulator: server Alibaba kemungkinan menolak device emulator.
  - **Etika**: kami tidak mengirim request ke server Alibaba produksi.

## 4. Analisis statis pendekatan unidbg (cara kerja)
```java
// (ringkas dari refrensi.txt + jianshu.com/p/d4c6cb0b639c)
emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.kopikenangan").build();
memory.setLibraryResolver(new AndroidResolver(23));
vm = emulator.createDalvikVM(new File(apkPath));     // butuh APK asli
DalvikModule dm = vm.loadLibrary(new File("libtiger_tally.so"), true);
dm.callJNI_OnLoad(emulator);
DvmClass TT = vm.resolveClass("com/aliyun/TigerTally/TigerTallyAPI");
TT.callStaticJniMethodObject(emu, "_genericNt1(I)I", 2);                 // init + pb()
TT.callStaticJniMethodObject(emu, "_genericNt2(ILjava/lang/String;)I",
                             2, new StringObject(vm, APP_KEY));          // app_key
DvmObject r = TT.callStaticJniMethodObject(emu, "_genericNt3(I[B)Ljava/lang/String;",
                             1, new ByteArray(vm, data.getBytes()));     // sign -> wToken
```
Mock wajib: `Build.MODEL/BRAND/DEVICE/RELEASE`, `PackageManager`, `SharedPreferences(tt_ak)`, dan **`pb()`** (jaringan).

## 5. Verifikasi input `_genericNt3` dari HAR
- Dari HAR register sukses: input `_genericNt3` = **request body plaintext** (`{"phone":...}`) — bukan ciphertext, bukan deviceid.
- `_genericNt3` sign dihitung app **sebelum** AES-CBC body (clsignature pun mengikuti plaintext). → konsisten dgn temuan sebelumnya.

## 6. Kesimpulan uji implementasi
- **unidbg tidak bisa dijalankan di sandbox ini** (Java 11 vs kebutuhan Java 8). Solusi: install JDK 8 di mesin user.
- **Meski jalan**, unidbg HANYA menghasilkan wToken valid jika `pb()` benar-benar mendaftar ke server Alibaba DAN lolos anti-emulator — itu yang gagal pada user (fingerprint `||`).
- **Implikasi**: unidbg black-box **bukan solusi mandiri**; tetap butuh koneksi keluar ke server Alibaba dgn identitas device yang lolos anti-emulator (= real device / cloud phone).
- **Tidak ada request nyata** ke server Alibaba/Kopi Kenangan yang dikirim (sesuai etika).
