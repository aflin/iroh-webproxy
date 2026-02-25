.PHONY: build static clean install install-static install-rampart

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  MUSL_TARGET := x86_64-unknown-linux-musl
else ifeq ($(ARCH),aarch64)
  MUSL_TARGET := aarch64-unknown-linux-musl
else ifeq ($(ARCH),armv7l)
  MUSL_TARGET := armv7-unknown-linux-musleabihf
else ifeq ($(ARCH),i686)
  MUSL_TARGET := i686-unknown-linux-musl
else
  MUSL_TARGET := $(ARCH)-unknown-linux-musl
endif

build:
	MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release

static:
	cargo build --release --target $(MUSL_TARGET)

clean:
	cargo clean

install: build
	cp target/release/iroh-webproxy /usr/local/bin/

install-static: static
	cp target/$(MUSL_TARGET)/release/iroh-webproxy /usr/local/bin/

install-rampart: build
	@command -v rampart >/dev/null 2>&1 || { echo "Error: rampart is not installed or not in PATH"; exit 1; }
	$(eval RAMPART_BIN := $(shell rampart -c "console.log(process.installPathBin)"))
	cp target/release/iroh-webproxy "$(RAMPART_BIN)/"
	@STATIC_BIN=$$(find target -path '*musl*/release/iroh-webproxy' -not -path '*/build/*' -type f 2>/dev/null | head -1); \
	if [ -n "$$STATIC_BIN" ]; then \
		cp "$$STATIC_BIN" "$(RAMPART_BIN)/iroh-webproxy-static"; \
	fi
