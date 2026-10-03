#!/usr/bin/env python3
"""Build quest-bridge into build/touchbridge.apk (NativeActivity + OpenXR, arm64).

Needs: Android NDK, build-tools (aapt2, zipalign, apksigner), platforms;android-34, a JDK
(for keytool/apksigner) and the Khronos OpenXR loader prefab.
Defaults match this PC; override with ANDROID_HOME, ANDROID_NDK, JAVA_HOME, OPENXR_PREFAB.

    python tools/build_bridge.py [--install SERIAL]
"""
import argparse
import glob
import os
import shutil
import subprocess
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK = os.environ.get("ANDROID_HOME", r"C:\Android\sdk")
NDK = os.environ.get("ANDROID_NDK") or sorted(glob.glob(os.path.join(SDK, "ndk", "*")))[-1]
JAVA = os.environ.get("JAVA_HOME") or sorted(glob.glob(os.path.expanduser(r"~\tools\jdk-21*")))[-1]
OPENXR_PREFAB = os.environ.get("OPENXR_PREFAB", r"C:\Android\openxr\prefab\modules")
OPENXR = os.path.join(OPENXR_PREFAB, "openxr_loader")
OPENXR_INC = os.path.join(OPENXR_PREFAB, "headers", "include")
BT = sorted(glob.glob(os.path.join(SDK, "build-tools", "*")))[-1]
OUT = os.path.join(ROOT, "build", "bridge")
API = 29


def run(cmd, **kw):
    print(">", " ".join(os.path.basename(c) if i == 0 else c for i, c in enumerate(cmd)))
    env = dict(os.environ, JAVA_HOME=JAVA, PATH=os.path.join(JAVA, "bin") + os.pathsep + os.environ["PATH"])
    subprocess.check_call(cmd, env=env, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--install", metavar="SERIAL", help="adb install -r to this device")
    a = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    bin_dir = os.path.join(NDK, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin")
    clang = os.path.join(bin_dir, f"aarch64-linux-android{API}-clang.cmd")
    clangxx = os.path.join(bin_dir, f"aarch64-linux-android{API}-clang++.cmd")
    glue_dir = os.path.join(NDK, "sources", "android", "native_app_glue")
    lib = os.path.join(OUT, "libtouchbridge.so")
    xr_lib_dir = os.path.join(OPENXR, "libs", "android.arm64-v8a")
    glue_obj = os.path.join(OUT, "android_native_app_glue.o")
    run([clang, "-c", "-fPIC", "-O2", os.path.join(glue_dir, "android_native_app_glue.c"), "-o", glue_obj])
    run([clangxx, "-shared", "-fPIC", "-O2", "-std=c++17", "-Wall",
         "-I", glue_dir, "-I", OPENXR_INC,
         os.path.join(ROOT, "quest-bridge", "src", "main.cpp"), glue_obj,
         "-L", xr_lib_dir, "-lopenxr_loader", "-landroid", "-llog", "-lEGL", "-lGLESv3",
         "-u", "ANativeActivity_onCreate", "-static-libstdc++", "-Wl,--no-undefined",
         "-o", lib])

    base = os.path.join(OUT, "base.apk")
    android_jar = os.path.join(SDK, "platforms", "android-34", "android.jar")
    run([os.path.join(BT, "aapt2.exe"), "link", "-o", base, "-I", android_jar,
         "--manifest", os.path.join(ROOT, "quest-bridge", "AndroidManifest.xml")])

    unsigned = os.path.join(OUT, "unsigned.apk")
    shutil.copy(base, unsigned)
    with zipfile.ZipFile(unsigned, "a") as z:
        # Uncompressed so the loader can mmap them (extractNativeLibs=false default on new targets).
        z.write(lib, "lib/arm64-v8a/libtouchbridge.so", compress_type=zipfile.ZIP_STORED)
        z.write(os.path.join(xr_lib_dir, "libopenxr_loader.so"), "lib/arm64-v8a/libopenxr_loader.so",
                compress_type=zipfile.ZIP_STORED)

    aligned = os.path.join(OUT, "aligned.apk")
    run([os.path.join(BT, "zipalign.exe"), "-f", "-p", "4", unsigned, aligned])

    ks = os.path.join(ROOT, "build", "debug.keystore")
    if not os.path.exists(ks):
        run([os.path.join(JAVA, "bin", "keytool.exe"), "-genkeypair", "-keystore", ks, "-storepass", "android",
             "-keypass", "android", "-alias", "touchframe", "-keyalg", "RSA", "-keysize", "2048",
             "-validity", "10000", "-dname", "CN=TouchFrame Debug"])
    apk = os.path.join(ROOT, "build", "touchbridge.apk")
    run([os.path.join(BT, "apksigner.bat"), "sign", "--ks", ks, "--ks-pass", "pass:android",
         "--out", apk, aligned])
    run([os.path.join(BT, "apksigner.bat"), "verify", apk])
    print(f"wrote {apk} ({os.path.getsize(apk) // 1024} KB)")

    if a.install:
        run(["adb", "-s", a.install, "install", "-r", apk])


if __name__ == "__main__":
    main()
