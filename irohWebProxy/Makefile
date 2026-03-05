RUST_PROJECT := ..
APP_NAME := irohWebProxy
APP_BUNDLE := $(APP_NAME).app
RUST_BINARY := $(RUST_PROJECT)/target/release/iroh-webproxy

.PHONY: all rust swift app dmg clean

all: rust swift app

rust:
	cd $(RUST_PROJECT) && cargo build --release

swift:
	swift build -c release

app: $(APP_BUNDLE)

$(APP_BUNDLE): swift
	@echo "Assembling $(APP_BUNDLE)..."
	mkdir -p $(APP_BUNDLE)/Contents/MacOS
	mkdir -p $(APP_BUNDLE)/Contents/Resources
	cp Info.plist $(APP_BUNDLE)/Contents/
	cp $$(swift build -c release --show-bin-path)/$(APP_NAME) $(APP_BUNDLE)/Contents/MacOS/
	@if [ -f "$(RUST_BINARY)" ]; then \
		cp $(RUST_BINARY) $(APP_BUNDLE)/Contents/Resources/iroh-webproxy; \
		echo "Bundled Rust binary into app."; \
	else \
		echo "Warning: Rust binary not found at $(RUST_BINARY). Run 'make rust' first to bundle it."; \
	fi
	codesign -s - --force --deep $(APP_BUNDLE)
	@echo "Ad-hoc signed $(APP_BUNDLE)."

DMG_NAME := $(APP_NAME).dmg
DMG_STAGING := .dmg-staging
DMG_TEMP := .dmg-rw.dmg
BG_IMAGE := scripts/dmg-background.png

dmg: app
	@echo "Creating $(DMG_NAME)..."
	rm -rf $(DMG_STAGING) $(DMG_TEMP) $(DMG_NAME)
	mkdir -p $(DMG_STAGING)/.background
	cp -r $(APP_BUNDLE) $(DMG_STAGING)/
	ln -s /Applications $(DMG_STAGING)/Applications
	cp $(BG_IMAGE) $(DMG_STAGING)/.background/background.png
	hdiutil create -srcfolder $(DMG_STAGING) -volname "$(APP_NAME)" \
		-fs HFS+ -fsargs "-c c=64,a=16,e=16" \
		-format UDRW -size 50m $(DMG_TEMP)
	@MOUNT_DIR=$$(hdiutil attach -readwrite -noverify -noautoopen $(DMG_TEMP) \
		| grep Apple_HFS | sed 's/.*Apple_HFS[[:space:]]*//' | sed 's/[[:space:]]*$$//'); \
	echo "Mounted at: $$MOUNT_DIR"; \
	osascript scripts/configure-dmg.applescript "$(APP_NAME)" "$(APP_BUNDLE)" || true; \
	sync; \
	hdiutil detach "$$MOUNT_DIR"
	hdiutil convert $(DMG_TEMP) -format UDZO -imagekey zlib-level=9 -o $(DMG_NAME)
	rm -rf $(DMG_STAGING) $(DMG_TEMP)
	@echo "Created $(DMG_NAME)"

clean:
	rm -rf .build $(APP_BUNDLE) $(DMG_NAME) $(DMG_STAGING) $(DMG_TEMP)

install: all
	cp -r $(APP_BUNDLE) /Applications/
	@echo "Installed $(APP_BUNDLE) to /Applications/"

uninstall:
	rm -rf /Applications/$(APP_BUNDLE)
	@echo "Removed $(APP_BUNDLE) from /Applications/"
