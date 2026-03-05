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
Browser  ──HTTP──▶  Client proxy  ══QUIC/iroh══▶  Server proxy  ──HTTP/S──▶  Backend
```

- **Client proxy** — Runs on your local machine. Listens for HTTP (and optionally
  HTTPS) connections. Reads the `Host` header to determine which iroh node to
  connect to, then tunnels all bytes through a QUIC bidirectional stream.

- **Server proxy** — Runs on the machine with the web server. Accepts iroh
  connections and forwards each stream to a local backend (HTTP or HTTPS). No
  HTTP parsing at all — pure byte-level forwarding.

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
the host suffix identifies the iroh node to connect to. The default suffix is
`.localhost` (configurable with `--host-suffix`).

| Format | Example | Notes |
|--------|---------|-------|
| Direct node ID | `http://<64-hex-chars>.localhost:8080/` | Works over plain HTTP with curl, some browsers |
| Split node ID | `http://<hex>.<hex>.localhost:8080/` | Insert a dot anywhere (see below) |
| DNS TXT lookup | `http://mysite.example.com.localhost:8080/` | Resolves node ID from DNS |

### Split node ID

DNS labels are limited to 63 characters, but an iroh node ID is 64 hex
characters. A 64-character label works in some cases (e.g. curl, Firefox over
plain HTTP) but will break in others — notably Chrome, and any browser when
using HTTPS/TLS (which validates hostnames against DNS rules).

To work around this, insert a dot anywhere in the node ID to split it into
labels shorter than 63 characters. The proxy strips all dots and reassembles
the hex string, so the dot placement doesn't matter:

```
http://ef4987c41374c912deb3cc03a420da8d.0b6e93740cc0295936a48e59fa4ba2df.localhost:8080/
http://ef4987c.41374c912deb3cc03a420da8d0b6e93740cc0295936a48e59fa4ba2df.localhost:8080/
http://ef4987c41374c912deb3cc.03a420da8d0b6e93740cc0295936a48e59fa4ba2df.localhost:8080/
```

All three examples above resolve to the same node ID.

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
| `-t, --target <TARGET>` | `127.0.0.1:8088` | Target web server (see [target formats](#target-formats)) |
| `--tls` | | Connect to target over TLS (implied by `https://` target) |
| `--insecure` | | Skip TLS certificate verification (implied when target is an IP) |
| `--target-hostname <HOST>` | | Hostname for TLS SNI and certificate verification |
| `-k, --secret-key <HEX>` | | Secret key as a 64-character hex string |
| `--key-file <PATH>` | `.iroh-webproxy-secret-key` | Path to the secret key file |
| `--no-key-save` | | Do not write the secret key to disk |
| `--no-key-load` | | Do not auto-load the key file on startup |
| `--log-level <LEVEL>` | `warn` | Log verbosity: `info`, `warn`, `error`, `none` |
| `--daemon` | | Detach from terminal and run in the background |
| `--pidfile <PATH>` | | Write the daemon PID to this file |

### Target formats

The `--target` flag accepts several formats:

| Target | Behavior |
|--------|----------|
| `ip:port` | Plain HTTP. Add `--tls` for HTTPS (`--insecure` implied). |
| `host:port` | Plain HTTP. Add `--tls` for HTTPS (verifies cert against hostname). |
| `http://host:port` | Plain HTTP. Error if `--tls` is also given. |
| `https://ip:port` | HTTPS with `--insecure` implied (no hostname to verify against). |
| `https://host:port` | HTTPS, verifies the certificate against `host`. |

When the target is an IP address with TLS, `--insecure` is implied automatically
because there is no hostname to verify the certificate against. Use
`--target-hostname` to supply a hostname and enable verification:

```sh
# HTTPS to a local IP, skip verification (--insecure implied)
iroh-webproxy server --target https://192.168.1.10:443

# HTTPS to a local IP, verify against a hostname
iroh-webproxy server --target https://192.168.1.10:443 --target-hostname myserver.local

# HTTPS to a hostname, certificate verified automatically
iroh-webproxy server --target https://myserver.local:443

# HTTPS to a hostname, skip verification explicitly
iroh-webproxy server --target https://myserver.local:443 --insecure
```

If the target URL omits the port, it defaults to 443 for `https://` and 80 for
`http://`.

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
| `--host-suffix <DOMAIN>` | `localhost` | Host suffix for routing (see [custom host suffix](#custom-host-suffix)) |
| `--http-port <PORT>` | `8080` | HTTP listen port |
| `--https-port <PORT>` | `8443` | HTTPS listen port (only when TLS is enabled) |
| `--ip-address <ADDR>` | `127.0.0.1` | IPv4 bind address |
| `--ipv6-address <ADDR>` | `::1` | IPv6 bind address |
| `--bind-all` | | Listen on all interfaces (`0.0.0.0` and `::`) |
| `-k, --secret-key <HEX>` | | Secret key as hex string or path to key file |
| `--log-level <LEVEL>` | `warn` | Log verbosity: `info`, `warn`, `error`, `none` |
| `--daemon` | | Detach from terminal and run in the background |
| `--pidfile <PATH>` | | Write the daemon PID to this file |

### TLS options

Enable HTTPS by providing exactly one of:

| Option | Description |
|--------|-------------|
| `--self-sign` | Generate a self-signed certificate (clients need `-k` with curl) |
| `--letsencrypt <DOMAIN>` | Load certs from `/etc/letsencrypt/live/<DOMAIN>/` |
| `--tls-cert <PATH> --tls-key <PATH>` | Load certificate and key from PEM files |

When TLS is enabled, the client listens on both the HTTP port and the HTTPS port.

### Custom host suffix

By default, the client routes requests based on `<nodeId>.localhost`. With a
wildcard DNS record pointing to the client machine, you can use a custom domain
instead:

```sh
# DNS: *.iroh.example.com → client machine IP
iroh-webproxy client --host-suffix iroh.example.com --bind-all
```

Browsers can then access proxied services at:

```
http://<nodeId>.iroh.example.com:8080/
```

When using `--self-sign` with a custom host suffix, the generated certificate
automatically includes `*.<suffix>` as a SAN. For production use, provide a
real wildcard certificate via `--letsencrypt` or `--tls-cert`/`--tls-key`.

## Daemon mode

Both `client` and `server` support `--daemon` to detach from the terminal using a
double-fork. The node ID is printed to stdout before daemonizing. Daemon mode
implies `--log-level none`.

```sh
# Capture the node ID, then the process backgrounds itself
NODE_ID=$(iroh-webproxy server --daemon)
echo "Server running with node ID: $NODE_ID"
```

Use `--pidfile` to record the daemon's PID for reliable process management:

```sh
iroh-webproxy server --daemon --pidfile /tmp/iroh-server.pid
# Later, stop the daemon:
kill "$(cat /tmp/iroh-server.pid)"
```

## Theoretical vulnerabilities

### Host header mismatch

The backend server receives requests with `Host: <nodeId>.localhost:8080` (or
whatever host suffix is configured) rather than its real hostname. Servers that
rely on the Host header for virtual hosting, CORS origin checks, or generating
absolute URLs may not work correctly. Most single-site backends are unaffected.

### Cookie scoping with custom host suffix

When using `--host-suffix` with a shared domain (e.g. `iroh.example.com`), a
backend server could theoretically set a cookie with
`Domain=.iroh.example.com`, which the browser would then send to every node ID
subdomain under that suffix. This would require the backend to specifically know
about and target the proxy's host suffix — no normal backend would do this
accidentally. Cookies set without a `Domain` attribute (the common case) are
scoped to the exact host and do not leak. Browser `localStorage` and other
storage APIs are strictly origin-scoped and are not affected.

### Man-in-the-middle at the client proxy

The client proxy terminates the browser's HTTP connection and has full access to
the plaintext request and response bytes. A modified client proxy could read or
alter traffic in transit. This is inherent to any local proxy (VPN clients, SSH
tunnels, reverse proxies all have the same property). In the typical
configuration — running on the same machine as the browser, bound to
`127.0.0.1` — this is not a practical concern since the operator of the machine
already has full access. It becomes relevant when the client is exposed to
other users' browsers via `--bind-all` or `--host-suffix` with a network-facing
DNS record, as those users are trusting the client proxy operator.

### Plaintext secret key storage

The server's secret key is stored as a hex string in a plain text file
(`.iroh-webproxy-secret-key`). On Unix the file is created with `0600`
permissions (owner-only read/write), but if the file is compromised an attacker
could impersonate the server with the same node ID. Use `--no-key-save` to
avoid writing the key to disk, or store it in a more secure location and pass
it via `--secret-key` or `--key-file`.

### Open proxy with --bind-all

When the client is started with `--bind-all`, it listens on all network
interfaces. Anyone on the network who can reach the client's port and who knows
a valid iroh node ID can use it as a gateway to that node's backend server. On
`127.0.0.1` (the default) only local processes can connect. If you need
network-facing access, consider firewall rules to restrict which hosts can reach
the client's ports.

## License

MIT
