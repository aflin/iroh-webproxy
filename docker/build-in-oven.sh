#!/bin/bash
# iroh-webproxy/docker/build-in-oven.sh <stage> -- runs INSIDE the oven.
# Invoke via docker/build.sh, not directly.
#
# stage = build | install
#
# Builds ONLY the iroh-webproxy CLI binary (workspace member "."); the
# iroh-webproxy-tray GUI member and the macOS Swift app are skipped.  Oven
# artifacts go under build/oven/ so the native target/ is left untouched.
set -euo pipefail

STAGE="${1:-build}"
WP=/wp
BUILD=$WP/build/oven
PREFIX="${RAMPART_PREFIX:-/usr/local/rampart-ml}"
BIN=iroh-webproxy

# Keep the crate cache + build tree inside the mounted repo (gitignored build/):
# cache persists across runs, and we never touch the host's native target/.
export CARGO_HOME="$WP/build/cargo-home"
export CARGO_TARGET_DIR="$BUILD/target"

enable_toolchain() {
    set +u
    # one of these globs won't match (only devtoolset OR gcc-toolset is present);
    # ls then exits non-zero -- tolerate it (|| true) so pipefail doesn't abort.
    sc=$(ls /opt/rh/gcc-toolset-*/enable /opt/rh/devtoolset-*/enable 2>/dev/null | sort -V | tail -1) || true
    [ -n "$sc" ] && source "$sc"
    set -u
}

case "$STAGE" in
  build)
    enable_toolchain
    echo "==> toolchain: $(gcc --version | head -1)"
    echo "==> rust: $(rustc --version)  cargo: $(cargo --version)"
    git config --global --add safe.directory '*' 2>/dev/null || true
    mkdir -p "$BUILD"
    # -p iroh-webproxy builds ONLY that workspace member (the tray GUI + macOS app
    # are never compiled), but cargo resolves the WHOLE workspace, so Cargo.lock
    # must cover the tray's deps too or --locked errors.  --locked pins the
    # committed versions verbatim -- no newer crates pulled (the whole point).
    # devtoolset is enabled first so cc-rs compiles ring/aws-lc-sys C with gcc 11.
    ( cd "$WP" && cargo build --release --locked -p "$BIN" )
    echo
    ls -l "$BUILD/target/release/$BIN"
    echo "==> iroh-webproxy build OK"
    ;;

  install)
    enable_toolchain   # for a matching `strip`
    [ -f "$BUILD/target/release/$BIN" ] || {
        echo "no build at $BUILD/target/release/$BIN -- run 'docker/build.sh build' first" >&2; exit 1; }
    install -d "$PREFIX/bin"
    install -m 755 "$BUILD/target/release/$BIN" "$PREFIX/bin/"
    strip "$PREFIX/bin/$BIN"
    if [ -d "$PREFIX/licenses" ]; then
        cp "$WP/LICENSE" "$PREFIX/licenses/iroh-webproxy.LICENSE" 2>/dev/null && echo "installed license" || true
    fi
    echo
    ls -l "$PREFIX/bin/$BIN"
    echo "==> iroh-webproxy install OK"
    ;;

  *)
    echo "unknown stage: $STAGE  (expected: build | install)" >&2
    exit 1
    ;;
esac
