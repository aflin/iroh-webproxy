# iroh-webproxy docker oven

Builds the **`iroh-webproxy` CLI binary** for the portable `centos7-x86_64`
target (glibc 2.17 floor) inside a self-contained [manylinux2014] "oven"
container.

`iroh-webproxy` is a standalone Rust binary (an HTTP/HTTPS proxy over iroh QUIC
tunnels). Rust statically links its std and the entire crate tree, so the
finished binary needs only **glibc + libgcc_s** — there is nothing to bundle.
Built natively it picks up your host's glibc (e.g. 2.34); built here it drops to
**2.17**, so it runs on CentOS 7 and everything newer.

> Builds **only the CLI** (workspace member `.`). The `iroh-webproxy-tray` GUI
> member and the macOS Swift app (`irohWebProxy/`) are skipped — `-p iroh-webproxy`
> means their GUI/system deps never get compiled. The musl fully-static build
> (`make static`) is a separate artifact and is *not* produced here.

```
docker/build.sh <stage>
```

## Commands

| Command | What it does |
|---|---|
| `docker/build.sh build` | Compile → `build/oven/target/release/iroh-webproxy` |
| `docker/build.sh install` | Install the binary into `/usr/local/rampart-ml/bin` |
| `docker/build.sh shell` | Interactive shell in the oven |
| `docker/build.sh save-image` | Persist the oven image to a `.tar.gz` (see below) |
| `docker/build.sh --rebuild-image [...]` | Force a fresh image first (after a `Dockerfile` edit) |

Typical flow:

```
docker/build.sh build      # -> build/oven/target/release/iroh-webproxy
docker/build.sh install    # -> /usr/local/rampart-ml/bin/iroh-webproxy
```

`install` strips the binary and (if that dir exists) copies `LICENSE` to
`…/licenses/iroh-webproxy.LICENSE`. Installing into rampart's `bin/` means `mkrp`
bundles it alongside the rampart binary.

> **First build needs network.** `cargo` fetches the whole crate tree from
> crates.io on the first run; the download cache then persists under
> `build/cargo-home/`, so later builds are offline-ish and incremental. The build
> uses **`--locked`**, so the committed `Cargo.lock` is honored verbatim — no
> newer crates are pulled. Note: because this is a workspace, `Cargo.lock` must be
> workspace-consistent (it must include the `iroh-webproxy-tray` member's deps) or
> `--locked` errors — so commit a complete lock.

## Mounted directories

Nothing host-facing is baked into the image — it's all bind-mounted at
`docker run` time. `$REPO` is the repo root (`/usr/local/src/iroh-webproxy`).

| Stage | Host path → container path | Mode |
|---|---|---|
| **build** | `/usr/local/src/iroh-webproxy` → `/wp` | rw |
| | `/etc/passwd` → `/etc/passwd` | ro |
| | `/etc/group` → `/etc/group` | ro |
| **install** | `/usr/local/src/iroh-webproxy` → `/wp` | rw |
| | `/usr/local/rampart-ml` → `/usr/local/rampart-ml` | rw |
| **shell** | `/usr/local/src/iroh-webproxy` → `/wp` | rw |

Why each one:

- **Repo (`/wp`)** — always rw: oven artifacts go to `build/oven/` (the cargo
  target via `CARGO_TARGET_DIR`, the crate cache in `build/cargo-home/`). Your
  native `target/` is **never** touched. `build/` is gitignored.
- **`/usr/local/rampart-ml`** — only mounted at **install** (rw), to drop the binary
  into `…/bin`. The **build is standalone** and does *not* mount it (unlike the
  module ovens, this binary doesn't link against rampart).
- **`/etc/passwd` + `/etc/group`** (ro) — only on `build`, which runs as your uid
  (`--user`) so the uid resolves to a name. `install` runs as root (to write the
  system bin dir), so it doesn't mount these.

Everything else (devtoolset-11, the Rust toolchain, cmake/perl for
`ring`/`aws-lc-sys`) lives **inside** the image.

## The oven image

The image (`iroh-webproxy-oven`) lives in your local docker store and persists
there across reboots and container runs — you don't need anything else to reuse
it. `build.sh` finds it automatically.

`save-image` additionally writes it to `build/iroh-webproxy-oven.image.tar.gz`
(a large file). This is only needed to:

1. **move it to another machine** (`docker load` there),
2. **back it up** before an aggressive prune / docker reinstall,
3. keep a frozen snapshot independent of the daemon.

If that tarball exists, `ensure_image` restores it with `docker load` instead of
rebuilding. After editing the `Dockerfile`, rebuild with `--rebuild-image`.

> A plain `docker image prune -f` only removes **dangling** (untagged) images and
> will not touch `iroh-webproxy-oven`. Only `docker rmi`, `docker image prune -a`,
> `docker system prune -a`, or a docker reinstall remove it — and even then the
> `Dockerfile` reproduces it deterministically (needs network).

## Notes

- Built with **Rust stable** (no `rust-toolchain` pin in the repo). Pin a version
  in the `Dockerfile` if you ever need a specific rustc.
- This oven shares the same toolchain as the `rampart-iroh` oven; the two images
  differ only in name.

[manylinux2014]: https://github.com/pypa/manylinux
