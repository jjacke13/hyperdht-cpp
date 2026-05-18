# Building the Android (Kotlin / JNI) wrapper

Cross-compiles `libhyperdht.a` + `libudx.a` for an Android ABI, links
them into the JNI bridge (`libhyperdht_jni.so`), then bundles the
Kotlin wrapper into a `.aar` or directly into an app.

Only **`arm64-v8a`** is tested end-to-end. 64-bit ARM is the only ABI
shipped by Google Play for non-legacy apps. Other ABIs should build
the same way but aren't covered by CI.

## Two paths

| Path | When | Build done by |
|------|------|---------------|
| **CI artifact** | Consuming the prebuilt JNI lib in an app | `.github/workflows/build.yml` → `build-android-arm64` |
| **Local cross-compile** | Changing the C++ / JNI code, ASAN runs | You, with the NDK |

The Gradle module `wrappers/kotlin/build.gradle.kts` does NOT build the
C library itself — its `CMakeLists.txt` only links pre-built static
libs from `libs/<ABI>/`.

## CI artifact path (recommended for app developers)

1. Run the `Build & Release` workflow (push a `v*` tag or trigger
   manually). It produces `hyperdht-android-arm64.tar.gz`.
2. Extract:
   ```bash
   tar xf hyperdht-android-arm64.tar.gz
   ```
3. Copy into your app:
   ```bash
   cp lib/libhyperdht_jni.so app/src/main/jniLibs/arm64-v8a/
   cp -r kotlin/com         app/src/main/java/
   ```
4. Build the app:
   ```bash
   ./gradlew assembleDebug
   ```

See `examples/android/` for a minimal working app.

## Local cross-compile path

Requires the Android NDK (r25+). On NixOS, `nix develop .#android`
provides everything. Otherwise install Android Studio's NDK and set
`$ANDROID_NDK`.

### 1. Cross-compile libsodium

```bash
git clone --depth 1 --branch stable https://github.com/jedisct1/libsodium.git /tmp/libsodium
cd /tmp/libsodium
./autogen.sh
export ANDROID_NDK_HOME=$ANDROID_NDK
export NDK_PLATFORM=android-26
export LIBSODIUM_FULL_BUILD=1
dist-build/android-armv8-a.sh
export SODIUM_PREFIX=/tmp/libsodium/libsodium-android-armv8-a+crypto
```

### 2. Cross-compile libuv

```bash
git clone --depth 1 --branch v1.51.0 https://github.com/libuv/libuv.git /tmp/libuv
cmake -B /tmp/libuv-build -S /tmp/libuv -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release -DLIBUV_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX=/tmp/libuv-android
ninja -C /tmp/libuv-build install
export UV_LIB=$(find /tmp/libuv-android/lib -name "*.a" | head -1)
```

### 3. Build hyperdht static libs

```bash
cd /path/to/hyperdht-cpp
cmake -B build-android -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DHYPERDHT_BUILD_TESTS=OFF \
  -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON \
  -DSODIUM_INCLUDE_DIR=$SODIUM_PREFIX/include \
  -DSODIUM_LIBRARY=$SODIUM_PREFIX/lib/libsodium.a \
  -DUV_INCLUDE_DIR=/tmp/libuv-android/include \
  -DUV_LIBRARY=$UV_LIB
ninja -C build-android
```

Produces `build-android/libhyperdht.a` + `build-android/libudx.a`.

### 4. Build the JNI bridge

```bash
NDK_CXX=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++
$NDK_CXX -std=c++20 -O2 -g -shared -fPIC \
  -I include -I deps/libudx/include \
  -I /tmp/libuv-android/include \
  -I $JAVA_HOME/include -I $JAVA_HOME/include/linux \
  wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp \
  build-android/libhyperdht.a build-android/libudx.a \
  $SODIUM_PREFIX/lib/libsodium.a $UV_LIB \
  -llog \
  -o build-android/libhyperdht_jni.so
```

### 5. Wire into Gradle

Two options:

**Option A — drop the prebuilt `.so` into an app:**

```bash
mkdir -p examples/android/app/src/main/jniLibs/arm64-v8a
cp build-android/libhyperdht_jni.so examples/android/app/src/main/jniLibs/arm64-v8a/
cp -r wrappers/kotlin/src/main/java/com examples/android/app/src/main/java/
cd examples/android
./gradlew assembleDebug
```

**Option B — let the Gradle library module rebuild via NDK:**

Drop the pre-built `.a` files (NOT the `.so`) into
`wrappers/kotlin/libs/arm64-v8a/`:

```bash
mkdir -p wrappers/kotlin/libs/arm64-v8a
cp build-android/libhyperdht.a build-android/libudx.a wrappers/kotlin/libs/arm64-v8a/
```

Then build the Android Library module. `wrappers/kotlin/CMakeLists.txt`
will pick them up and link `libhyperdht_jni.so` itself.

## ASAN build (memory bug hunting)

Use the manually-triggered workflow `.github/workflows/android-asan.yml`
or replicate locally — flip `-DCMAKE_BUILD_TYPE=Debug` and add
`-fsanitize=address -fno-omit-frame-pointer -g -O1` to both the static
libs and the JNI link command. Bundle `libclang_rt.asan-aarch64-android.so`
from the NDK alongside the JNI lib and configure ASAN via `wrap.sh`
inside the app.

Reference scenario: `QUERY-PUSH-CLOSEST-WAF-CRASH.md` documents the
hardened_malloc-on-GrapheneOS WAF crash these builds chase.

## Configuration knobs

- **Minimum SDK**: 26 (Android 8.0). Set in `build.gradle.kts:minSdk`.
- **NDK platform**: `android-26`. Set in CMake invocation.
- **STL**: `c++_shared`. Set in `build.gradle.kts` externalNativeBuild.
- **Java level**: 17 (source + target + Kotlin jvmTarget).
- **Kotlin coroutines**: `kotlinx-coroutines-android:1.8.1`.

## Reference

- Kotlin wrapper source: `wrappers/kotlin/src/main/`
- JNI bridge: `wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp`
- Working Android app: `examples/android/`
- ASAN workflow: `.github/workflows/android-asan.yml`
