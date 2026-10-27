# Kotlin connection-error regression

Run from the repository root with a JDK, Kotlin compiler and coroutines JAR
already installed. This tests the real host JNI bridge, C error descriptions,
Kotlin exception codes/messages, and a failed native connection callback.
It does not build Android native code or test an Android device.

Set `JAVA_HOME`, `KOTLIN_HOME`, `COROUTINES_JAR` and `BUILD_DIR` to local paths.
`BUILD_DIR` must contain a CMake build of this revision with
`CMAKE_POSITION_INDEPENDENT_CODE=ON` and its `libhyperdht.a`/`libudx.a`.

```sh
c++ -std=c++20 -shared -fPIC -pthread \
  -Iinclude -Ideps/libudx/include \
  -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
  $(pkg-config --cflags libsodium libuv) \
  wrappers/kotlin/src/main/cpp/hyperdht_jni.cpp \
  "$BUILD_DIR/libhyperdht.a" "$BUILD_DIR/libudx.a" \
  $(pkg-config --libs libsodium libuv) -o "$BUILD_DIR/libhyperdht_jni.so"
"$KOTLIN_HOME/bin/kotlinc" wrappers/kotlin/src/main/kotlin/com/hyperdht/*.kt \
  test/kotlin/ConnectErrors.kt -cp "$COROUTINES_JAR" \
  -include-runtime -d "$BUILD_DIR/kotlin-errors.jar"
"$JAVA_HOME/bin/java" -Xcheck:jni -Djava.library.path="$BUILD_DIR" \
  -cp "$BUILD_DIR/kotlin-errors.jar:$COROUTINES_JAR" com.hyperdht.ConnectErrorsKt
```
