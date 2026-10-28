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

For the read-completion test, add `test/kotlin/read_callback_fixture.cpp` and
`-Wl,--wrap=hyperdht_immutable_get` to the host JNI link command. Compile
`test/kotlin/ReadErrors.kt` instead of `ConnectErrors.kt` and run
`com.hyperdht.ReadErrorsTest`. This GNU-linker fixture injects C completion
callbacks to test the real JNI/Kotlin handler; it is not a transport test.
Real UDP/query-completion tests are `ReadStatus/StorageReadErrors.*` in
`test_hyperdht`, including explicit cancellation and normal read misses.

For immediate-return tests, use `test/kotlin/immediate_return_fixture.cpp`
and linker flags `-Wl,--wrap=hyperdht_connect`,
`-Wl,--wrap=hyperdht_immutable_get`, `-Wl,--wrap=hyperdht_immutable_put`, and
`-Wl,--wrap=hyperdht_mutable_put`. Compile `ImmediateErrors.kt` and run
`com.hyperdht.ImmediateErrorsTest`. Empty puts and invalid ping addresses
exercise real C validation; the fixture injects get/connect rejections and
accepted synchronous callbacks. The timeout guards catch ignored returns.
Run against both the primary wrapper and the Android example's Kotlin sources.

With the same immediate-return fixture, compile `ContextErrors.kt` and run
`com.hyperdht.ContextErrorsTest` to check descriptions and numeric codes for
validation and query failures. It also checks JNI system descriptions using
a real invalid-address bind failure. `ReadErrors.kt` checks query success,
miss, failure, cancellation and unknown status messages with its read fixture.

Error domains deliberately overlap numerically. C callers use
`hyperdht_connect_strerror` for connection callbacks, `hyperdht_query_strerror`
for storage/query completions, `hyperdht_call_strerror` for the documented
immediate submission statuses, and `hyperdht_system_strerror` for raw libuv
statuses (such as bind). Kotlin exposes the same distinction via `Errors`.
Existing `Errors.describe` and default `DhtException(code)` retain connection
semantics. Rebuild JNI/core together with the updated Kotlin sources; an old
native library does not provide the new description entry points.
