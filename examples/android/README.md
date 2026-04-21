# HyperDHT Android Example

Minimal Android app that tests the HyperDHT Kotlin/JNI wrapper.

## Setup

1. Download `hyperdht-android-arm64.tar.gz` from the GitHub Actions artifacts

2. Extract and copy the JNI shared library:
   ```bash
   tar xf hyperdht-android-arm64.tar.gz
   cp lib/libhyperdht_jni.so app/src/main/jniLibs/arm64-v8a/
   ```

3. Copy the Kotlin wrapper sources:
   ```bash
   cp -r kotlin/com app/src/main/java/
   ```

## Build

```bash
# From this directory
nix develop .#android  # or have Android SDK + Gradle installed

./gradlew assembleDebug
```

The APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

## Install & Test

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

Or transfer the APK to your phone and install manually.

## What it does

- Loads `libhyperdht_jni.so` (the native P2P library)
- Connects to the echo server at `b7c5c4e9...`
- Sends a message over the encrypted P2P tunnel
- Displays the echoed response
