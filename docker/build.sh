#!/bin/sh
# build.sh <stage> -- build the iroh-webproxy CLI binary in a manylinux2014
#                  "oven" (glibc 2.17).  CLI only; the tray GUI + macOS app are skipped.
#
#   build.sh build        # compile -> build/oven/target/release/iroh-webproxy
#   build.sh install      # install the binary into <prefix>/bin
#   build.sh shell        # interactive shell in the oven
#   build.sh save-image   # persist the oven image to a .tar.gz
#
#   Flags:
#      --rebuild-image    # force a fresh oven image first (after a Dockerfile edit)
#      -d <dir>           # install into <dir> instead of /usr/local/rampart-2_17
#
# What it touches:
#   build      -> build/oven/   (cargo cache persists under build/cargo-home)
#   install    -> adds the iroh-webproxy binary to <prefix>/bin
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
PREFIX_DIR="/usr/local/rampart-2_17"; [ "${1:-}" = "-d" ] && { PREFIX_DIR="$2"; shift 2; }
IMAGE=iroh-webproxy-oven
IMAGE_TAR="$REPO/build/$IMAGE.image.tar.gz"   # persisted image (gitignored /build/)

# Persist the image to a .tar.gz (large) for `docker load` after a prune or to
# move it to another machine.  Invoked only by the `save-image` stage -- builds
# no longer create the tarball automatically.
save_image() {
    mkdir -p "$(dirname "$IMAGE_TAR")"
    echo "==> persisting image to $IMAGE_TAR"
    docker save "$IMAGE" | gzip > "$IMAGE_TAR"
}

if [ "$1" = "--rebuild-image" ]; then
    # Cache-aware rebuild: picks up Dockerfile edits while reusing cached layers
    # (the Rust toolchain install).  Use a manual `docker rmi` + this for a true
    # from-scratch build.
    docker build --build-arg ARCH="$(uname -m)" -t "$IMAGE" "$HERE"
    shift
fi

# Reuse the image if loaded; else restore from the persisted tarball (no
# rebuild); else build once.  The toolchain only ever installs on the
# first-ever image build or --rebuild-image.
ensure_image() {
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "==> using existing oven image '$IMAGE' (run --rebuild-image after Dockerfile edits)"
        return
    fi
    if [ -f "$IMAGE_TAR" ]; then
        echo "==> restoring oven image from $IMAGE_TAR (no rebuild)"
        docker load -i "$IMAGE_TAR" && return
        echo "   (load failed -- rebuilding)"
    fi
    echo "==> building oven image '$IMAGE' (one-time: devtoolset-11 + Rust)…"
    docker build --build-arg ARCH="$(uname -m)" -t "$IMAGE" "$HERE"
}

require_rampart() {
    [ -x "$PREFIX_DIR/bin/rampart" ] || {
        echo "missing $PREFIX_DIR/bin/rampart -- install the centos7 rampart first" >&2
        exit 1; }
}

do_build() {
    ensure_image
    echo "==> [iroh-webproxy build] compiling into build/oven/…"
    # As the invoking user; standalone build, so the rampart prefix is NOT
    # mounted.  --network is default (cargo fetches crates on the first run).
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp -e RAMPART_PREFIX="$PREFIX_DIR" \
        -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro \
        -v "$REPO:/wp" -w /wp \
        "$IMAGE" /wp/docker/build-in-oven.sh build
}

do_install() {
    ensure_image
    require_rampart
    [ -f "$REPO/build/oven/target/release/iroh-webproxy" ] || {
        echo "no build -- run 'docker/build.sh build' first" >&2; exit 1; }
    echo "==> [iroh-webproxy install] installing binary into $PREFIX_DIR/bin…"
    # Root so it can write the system bin dir; the prefix is mounted rw at its real path.
    docker run --rm \
        -e HOME=/tmp -e RAMPART_PREFIX="$PREFIX_DIR" \
        -v "$REPO:/wp" -w /wp \
        -v "$PREFIX_DIR":"$PREFIX_DIR" \
        "$IMAGE" /wp/docker/build-in-oven.sh install
}

STAGE="${1:-}"
case "$STAGE" in
    build)   do_build ;;
    install) do_install ;;
    save-image)
        docker image inspect "$IMAGE" >/dev/null 2>&1 || {
            echo "image '$IMAGE' not built yet -- run 'docker/build.sh build' first" >&2; exit 1; }
        save_image ;;
    shell)
        ensure_image
        exec docker run --rm -it -e HOME=/tmp -e RAMPART_PREFIX="$PREFIX_DIR" \
            -v "$REPO:/wp" -w /wp "$IMAGE" /bin/bash ;;
    ""|-h|--help)
        sed -n '2,/^set -e/{/^set -e/!p}' "$0" | sed 's/^# \{0,1\}//' ;;
    *)
        echo "unknown stage: $STAGE  (build | install | save-image | shell)" >&2
        exit 1 ;;
esac
