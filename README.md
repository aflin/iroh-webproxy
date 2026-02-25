# iroh-webproxy

HTTP/HTTPS web proxy over [iroh](https://iroh.computer/) QUIC tunnels. Exposes a
remote web server on your local machine through an encrypted peer-to-peer
connection — no port forwarding, no public IP required.

All bytes are forwarded verbatim between the browser and the backend. There is no
HTTP parsing or rewriting beyond reading the `Host` header for routing. This means
cookies, WebSocket upgrades, keep-alive, and every other HTTP feature work
transparently.

## Architecture

```
Browser  ──HTTP──▶  Client proxy  ══QUIC/iroh══▶  Server proxy  ──HTTP──▶  Backend
```

- **Client proxy** — Runs on your local machine. Listens for HTTP (and optionally
  HTTPS) connections. Reads the `Host` header to determine which iroh node to
  connect to, then tunnels all bytes through a QUIC bidirectional stream.

- **Server proxy** — Runs on the machine with the web server. Accepts iroh
  connections and forwards each stream to a local HTTP backend. No HTTP parsing
  at all — pure byte-level forwarding.

## Building

Requires Rust 1.75+ and cargo.

```sh
# Standard build (dynamically linked against glibc)
make

# Fully static build (musl — runs on any Linux distro)
# Requires: rustup target add x86_64-unknown-linux-musl
# Requires: apt install musl-tools  (or equivalent)
make static

# Install to /usr/local/bin/
make install          # glibc build
make install-static   # musl build

# Clean build artifacts
make clean
```

Or directly with cargo:

```sh
cargo build --release
# Binary at target/release/iroh-webproxy
```

## Quick start

On the **server** machine (where your web server runs on port 8088):

```sh
iroh-webproxy server
# Prints the node ID, e.g.: ef4987c41374c912deb3cc03a420da8d0b6e93740cc0295936a48e59fa4ba2df
```

On the **client** machine:

```sh
iroh-webproxy client
# Prints its own node ID (not needed for basic usage)
```

Open a browser to:

```
http://<nodeId>.localhost:8080/
```

Or with curl:

```sh
curl -H "Host: <nodeId>.localhost:8080" http://127.0.0.1:8080/
```

## URL formats

The client proxy routes requests based on the `Host` header. The subdomain before
`.localhost` identifies the iroh node to connect to.

| Format | Example | Notes |
|--------|---------|-------|
| Direct node ID | `http://<64-hex-chars>.localhost:8080/` | Firefox, curl |
| Split node ID | `http://<32hex>.<32hex>.localhost:8080/` | Chrome (63-char DNS label limit) |
| DNS TXT lookup | `http://mysite.example.com.localhost:8080/` | Resolves node ID from DNS |

### Chrome split node ID

Chrome enforces the DNS 63-character label limit, so a 64-character node ID won't
work as a single subdomain label. Instead, split the node ID into two 32-character
halves separated by a dot:

```
http://ef4987c41374c912deb3cc03a420da8d.0b6e93740cc0295936a48e59fa4ba2df.localhost:8080/
```

### DNS TXT record resolution

If the subdomain is not a hex node ID, the client treats it as a domain name and
performs a DNS TXT record lookup. This lets you use friendly URLs like:

```
http://mysite.example.com.localhost:8080/
```

The proxy strips `.localhost`, looks up TXT records for `mysite.example.com`, and
searches for a record with the format:

```
mysite.example.com.  IN  TXT  "iroh-nodeId=<64-char-hex-node-id>"
```

The key `iroh-nodeId` is case-insensitive. If multiple TXT records match, the last
one is used.

The resolver reads `/etc/resolv.conf`, so `search` directives apply. If your
`resolv.conf` contains `search example.com`, then `http://mysite.localhost:8080/`
will resolve `mysite.example.com` automatically.

## Server options

```
iroh-webproxy server [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --target <ADDR>` | `127.0.0.1:8088` | Local web server address to forward requests to |
| `-k, --secret-key <HEX>` | | Secret key as a 64-character hex string |
| `--key-file <PATH>` | `.iroh-webproxy-secret-key` | Path to the secret key file |
| `--no-key-save` | | Do not write the secret key to disk |
| `--no-key-load` | | Do not auto-load the key file on startup |
| `--log-level <LEVEL>` | `warn` | Log verbosity: `info`, `warn`, `error`, `none` |
| `--daemon` | | Detach from terminal and run in the background |

### Key persistence

By default the server saves its secret key to `.iroh-webproxy-secret-key` in
the current directory and reloads it on subsequent runs. This keeps the node ID
stable across restarts. Use `--no-key-save` to disable saving, or `--no-key-load`
to ignore any existing key file.

## Client options

```
iroh-webproxy client [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--http-port <PORT>` | `8080` | HTTP listen port |
| `--https-port <PORT>` | `8443` | HTTPS listen port (only when TLS is enabled) |
| `--ip-address <ADDR>` | `127.0.0.1` | IPv4 bind address |
| `--ipv6-address <ADDR>` | `::1` | IPv6 bind address |
| `--bind-all` | | Listen on all interfaces (`0.0.0.0` and `::`) |
| `-k, --secret-key <HEX>` | | Secret key as hex string or path to key file |
| `--log-level <LEVEL>` | `warn` | Log verbosity: `info`, `warn`, `error`, `none` |
| `--daemon` | | Detach from terminal and run in the background |

### TLS options

Enable HTTPS by providing exactly one of:

| Option | Description |
|--------|-------------|
| `--self-sign` | Generate a self-signed certificate (clients need `-k` with curl) |
| `--letsencrypt <DOMAIN>` | Load certs from `/etc/letsencrypt/live/<DOMAIN>/` |
| `--tls-cert <PATH> --tls-key <PATH>` | Load certificate and key from PEM files |

When TLS is enabled, the client listens on both the HTTP port and the HTTPS port.

## Daemon mode

Both `client` and `server` support `--daemon` to detach from the terminal using a
double-fork. The node ID is printed to stdout before daemonizing. Daemon mode
implies `--log-level none`.

```sh
# Capture the node ID, then the process backgrounds itself
NODE_ID=$(iroh-webproxy server --daemon)
echo "Server running with node ID: $NODE_ID"
```

## License

MIT
