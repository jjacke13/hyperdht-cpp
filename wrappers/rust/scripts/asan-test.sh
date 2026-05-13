#!/usr/bin/env bash
# Run the Rust wrapper test suite against an ASAN-instrumented C library.
#
# Why C-side only? Stable rustc rejects `-Zsanitizer=address`. ASAN'ing
# the C side still catches the bugs that actually happen at the unsafe
# Box::from_raw <-> C library lifecycle boundary. Pure Rust safety is
# enforced by the type system anyway.
#
# Run from the repo root:
#     bash wrappers/rust/scripts/asan-test.sh
#
# Tweakables via env:
#     HYPERDHT_ASAN_OPTS  -- extra ASAN_OPTIONS (default: leak detection on)
#     HYPERDHT_KEEP_BUILD -- if set, skips `cargo clean` before the run

set -euo pipefail

cd "$(git rev-parse --show-toplevel)/wrappers/rust"

if [ -z "${HYPERDHT_KEEP_BUILD:-}" ]; then
    echo "  [asan] cargo clean (rebuild C library with -fsanitize=address)"
    cargo clean
fi

# hyperdht-sys/build.rs and hyperdht/build.rs both look at this env
# var and emit `-fsanitize=address` for cmake + libasan_preinit.o /
# libasan.so as link-args for downstream binaries.
export HYPERDHT_ASAN=1
export RUSTFLAGS="-C link-arg=-fno-omit-frame-pointer"

# ASAN runtime options:
#   detect_leaks=1     LSan on (catches Box::into_raw orphans).
#   halt_on_error=0    print all findings, don't stop at the first.
#   abort_on_error=0   exit cleanly so cargo collects the result.
#   strict_string_checks=1            harder strncpy/strcat checks.
#   detect_stack_use_after_return=1   extra UAF coverage for stack frames.
#   print_stats=1      summary at process exit.
export ASAN_OPTIONS="${HYPERDHT_ASAN_OPTS:-detect_leaks=1:halt_on_error=0:abort_on_error=0:strict_string_checks=1:detect_stack_use_after_return=1:print_stats=1}"

# LSan suppressions for libuv / libsodium one-time globals that
# legitimately leak on shutdown.
SUPP_FILE="$(git rev-parse --show-toplevel)/wrappers/rust/scripts/asan-suppressions.txt"
if [ -f "$SUPP_FILE" ]; then
    export LSAN_OPTIONS="suppressions=${SUPP_FILE}:print_suppressions=0"
fi

# ASAN must be the FIRST shared library loaded into the process so its
# interceptors override the system malloc/free etc. Setting LD_PRELOAD
# here makes the test binaries (run as cargo subprocesses) inherit it.
LIBASAN_SO="$(gcc -print-file-name=libasan.so)"
if [ ! -f "$LIBASAN_SO" ]; then
    echo "ERROR: gcc -print-file-name=libasan.so returned a non-file: $LIBASAN_SO"
    exit 1
fi
echo "  [asan] LD_PRELOAD = $LIBASAN_SO"

# We can't just `export LD_PRELOAD=…` for the whole script — cargo +
# rustc themselves would inherit it and ASan would intercept their
# memory operations (lots of harmless noise + occasional crashes).
# Instead: build first (LD_PRELOAD off), then walk every test binary
# under target/debug/deps/ and run it with LD_PRELOAD set.

echo "  [asan] HYPERDHT_ASAN=1 — compiling..."
cargo test --jobs 1 --no-run 2>&1 | tail -5

echo
echo "  [asan] running test binaries with LD_PRELOAD set..."
echo

# Collect every executable test binary cargo just produced.
shopt -s nullglob
fail_count=0
leak_count=0
for bin in target/debug/deps/*; do
    if [ ! -x "$bin" ] || [ -d "$bin" ]; then
        continue
    fi
    case "$(file -b "$bin" 2>/dev/null)" in
        *ELF*executable*) ;;
        *) continue ;;
    esac
    name="$(basename "$bin")"
    case "$name" in
        *-*) ;;
        *) continue ;;
    esac

    echo "  ─── $name ─────────────────────────────────────────────"
    LOG="$(mktemp)"
    set +e
    LD_PRELOAD="$LIBASAN_SO" "$bin" --test-threads=1 2>&1 | tee "$LOG"
    rc=${PIPESTATUS[0]}
    set -e
    if [ $rc -ne 0 ]; then
        echo "  ✘ $name failed (exit=$rc)"
        fail_count=$((fail_count + 1))
    fi
    if grep -q "ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|SUMMARY: AddressSanitizer" "$LOG"; then
        leak_count=$((leak_count + 1))
    fi
    rm -f "$LOG"
    echo
done

echo
if [ $fail_count -eq 0 ] && [ $leak_count -eq 0 ]; then
    echo "  [asan] ✓ all test binaries passed cleanly (no ASAN findings)"
    exit 0
fi
echo "  [asan] FINDINGS:"
[ $fail_count -gt 0 ] && echo "    ${fail_count} test binary(ies) returned non-zero"
[ $leak_count -gt 0 ] && echo "    ${leak_count} test binary(ies) reported AddressSanitizer/LeakSanitizer findings"
echo "  [asan] re-run with HYPERDHT_KEEP_BUILD=1 + --no-capture to inspect failures"
exit 1
