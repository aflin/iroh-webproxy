.PHONY: build static clean install install-static install-rampart app dmg

ARCH := $(shell uname -m)
OS := $(shell uname -s)
HAS_SWIFT := $(shell command -v swift >/dev/null 2>&1 && echo yes || echo no)

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
ifeq ($(OS),Darwin)
ifeq ($(HAS_SWIFT),yes)
	@$(MAKE) -C irohWebProxy app
else
	@echo "Warning: Swift toolchain not found. Skipping macOS app build."
	@echo "Install Xcode or Command Line Tools to build irohWebProxy.app."
endif
endif

static:
	cargo build --release --target $(MUSL_TARGET)

app:
ifeq ($(OS),Darwin)
ifeq ($(HAS_SWIFT),yes)
	@$(MAKE) -C irohWebProxy app
else
	@echo "Error: Swift toolchain not found. Cannot build macOS app."
	@echo "Install Xcode or Command Line Tools to build irohWebProxy.app."
	@exit 1
endif
else
	@echo "Error: macOS app can only be built on macOS."
	@exit 1
endif

dmg: build
ifeq ($(OS),Darwin)
ifeq ($(HAS_SWIFT),yes)
	@$(MAKE) -C irohWebProxy dmg
else
	@echo "Error: Swift toolchain not found. Cannot build DMG."
	@exit 1
endif
else
	@echo "Error: DMG can only be built on macOS."
	@exit 1
endif

clean:
	cargo clean
	@if [ -d irohWebProxy ]; then $(MAKE) -C irohWebProxy clean; fi

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
