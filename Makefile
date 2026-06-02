#
# Makefile for Sliver
#

GO ?= go
ARTIFACT_SUFFIX ?=
ENV =
TAGS ?= -tags go_sqlite
CGO_ENABLED = 0

ifneq (,$(findstring cgo_sqlite,$(TAGS)))
	CGO_ENABLED = 1
endif

MIN_SUPPORTED_GO_MAJOR_VERSION = 1
MIN_SUPPORTED_GO_MINOR_VERSION = 25
GO_VERSION_VALIDATION_ERR_MSG = Golang version is not supported, please update to at least $(MIN_SUPPORTED_GO_MAJOR_VERSION).$(MIN_SUPPORTED_GO_MINOR_VERSION)

SLIVER_PUBLIC_KEY ?= RWTZPg959v3b7tLG7VzKHRB1/QT+d3c71Uzetfa44qAoX5rH7mGoQTTR
ARMORY_PUBLIC_KEY ?= RWSBpxpRWDrD7Fe+VvRE3c2VEDC2NK80rlNCj+BX0gz44Xw07r6KQD9L
ARMORY_REPO_URL ?= https://api.github.com/repos/sliverarmory/armory/releases
CLIENT_ASSETS_PKG = github.com/sudosoc/SUDOSOC-C2/client/assets
SLIVER_UPDATE_PKG = github.com/sudosoc/SUDOSOC-C2/client/command/update
# Only validate protoc itself at Makefile parse time.
# protoc-gen-go and protoc-gen-go-grpc are installed automatically by `make pb`
# into $(go env GOPATH)/bin and validated in the recipe, not at parse time.
PB_COMPILERS = protoc

ifneq ($(OS),Windows_NT)

#
# Prerequisites
#
# https://stackoverflow.com/questions/5618615/check-if-a-program-exists-from-a-makefile
EXECUTABLES = uname sed git date cut $(GO)
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH")))

#
# Build Information
#
GO_MAJOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)

LDFLAGS = -ldflags "-s -w \
	-X $(SLIVER_UPDATE_PKG).SliverPublicKey=$(SLIVER_PUBLIC_KEY) \
	-X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) \
	-X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"

# Debug builds shouldn't be stripped (-s -w flags)
LDFLAGS_DEBUG = -ldflags "-X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) \
	-X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"

SED_INPLACE := sed -i
STATIC_TARGET := linux

UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)

# Programs required for generating protobuf/grpc files
ifeq ($(MAKECMDGOALS), pb)
	K := $(foreach exec,$(PB_COMPILERS),\
			$(if $(shell which $(exec)),some string,$(error "Missing protobuf util $(exec) in PATH")))
endif

# *** Darwin ***
ifeq ($(UNAME_S),Darwin)
	SED_INPLACE := sed -i ''
	STATIC_TARGET := macos
endif

# If no target is specified, determine GOARCH
ifeq ($(UNAME_P),arm)
	ifeq ($(MAKECMDGOALS), )
		ifeq ($(origin GOARCH), undefined)
			ENV += GOARCH=arm64
		endif
	endif
endif

ifeq ($(MAKECMDGOALS), linux)
	# Redefine LDFLAGS to add the static part
	LDFLAGS = -ldflags "-s -w \
		-extldflags '-static' \
		-X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) \
		-X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"
endif

# ─── Web UI ───────────────────────────────────────────────────────────────────
# Set UI_SKIP=1 to skip the React build step (cross-compilation / fast re-runs
# when the UI is already built).
#   make UI_SKIP=1 linux-amd64
UI_SKIP ?= 0

ifeq ($(UI_SKIP),0)
_UI_DEP := ui
else
_UI_DEP :=
endif

#
# Targets
#

## Build the React Web UI (outputs to server/web/ui/ embedded via go:embed)
## The placeholder server/web/ui/index.html is always committed to git so
## go:embed compiles even without running this target first.
.PHONY: ui
ui:
	cd webui && npm install && npm run build
	@echo "[+] Web UI built → server/web/ui/"

## Download Go toolchains + Garble + Zig for implant generation (~500 MB)
## Required for full `generate` functionality; takes 10-30 min depending on internet speed.
.PHONY: assets
assets:
	$(ENV) $(GO) run -mod=vendor ./util/cmd/assets
	touch ./.downloaded_assets
	@echo "[+] Assets downloaded → server/assets/fs/"

## Create minimal placeholder assets so the server compiles without downloading toolchains.
## The server will run (listeners, sessions, Web UI, TUI, etc.) but `generate` implants
## will not work until `make assets` is run.
.PHONY: placeholders
placeholders:
	@echo "[*] Creating placeholder assets for compilation without toolchain download..."
	@mkdir -p server/assets/fs/linux/amd64 server/assets/fs/linux/arm64
	@mkdir -p server/assets/fs/darwin/amd64 server/assets/fs/darwin/arm64
	@mkdir -p server/assets/fs/windows/amd64
	@[ -f server/assets/fs/linux/amd64/placeholder.txt ]   || echo "placeholder" > server/assets/fs/linux/amd64/placeholder.txt
	@[ -f server/assets/fs/linux/arm64/placeholder.txt ]   || echo "placeholder" > server/assets/fs/linux/arm64/placeholder.txt
	@[ -f server/assets/fs/darwin/amd64/placeholder.txt ]  || echo "placeholder" > server/assets/fs/darwin/amd64/placeholder.txt
	@[ -f server/assets/fs/darwin/arm64/placeholder.txt ]  || echo "placeholder" > server/assets/fs/darwin/arm64/placeholder.txt
	@[ -f server/assets/fs/windows/amd64/placeholder.txt ] || echo "placeholder" > server/assets/fs/windows/amd64/placeholder.txt
	@if [ ! -f server/assets/fs/placeholder.zip ]; then \
		cd server/assets/fs && zip -q placeholder.zip empty.txt && cd ../../..; \
	fi
	@[ -f server/web/ui/index.html ] || $(MAKE) ui
	@touch .downloaded_assets
	@echo "[+] Placeholder assets created — server will compile and run."
	@echo "    Run 'make assets' later to enable full implant generation."

## Remove compiled Web UI built assets (keeps placeholder index.html)
.PHONY: clean-ui
clean-ui:
	rm -rf server/web/ui/assets
	@echo "[-] Web UI assets cleaned (placeholder index.html preserved)"

## Default: build Web UI + server + client for the current platform
## If toolchain assets are missing, automatically creates placeholders (no implant generation).
## For full implant generation: run `make assets` first, then `make`.
.PHONY: default
default: clean validate-go-version $(_UI_DEP)
	@if [ ! -f .downloaded_assets ]; then \
		echo "[!] Toolchain assets not downloaded."; \
		echo "    Creating placeholders so the server compiles (implant generation will be limited)."; \
		echo "    Run 'make assets' later for full implant generation support."; \
		$(MAKE) placeholders; \
	fi
	$(ENV) $(if $(GOOS),GOOS=$(GOOS)) $(if $(GOARCH),GOARCH=$(GOARCH)) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	$(ENV) $(if $(GOOS),GOOS=$(GOOS)) $(if $(GOARCH),GOARCH=$(GOARCH)) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client
	@echo "[+] Build complete → sudosoc-server$(ARTIFACT_SUFFIX) + sudosoc-client$(ARTIFACT_SUFFIX)"

## Rebuild only the Go binaries.
## Auto-creates placeholder assets/UI if missing so the build always succeeds.
.PHONY: server-only
server-only:
	@[ -f .downloaded_assets ]          || $(MAKE) placeholders
	@[ -f server/web/ui/index.html ]    || $(MAKE) ui
	$(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	$(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client
	@echo "[+] Go binaries rebuilt"

# Allows you to build a CGO-free client for any target
# NOTE: WireGuard is not supported on all platforms, but most 64-bit GOOS/GOARCH combinations should work.
.PHONY: client
client: clean .downloaded_assets validate-go-version
	$(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client ./client

.PHONY: macos-amd64
macos-amd64: clean $(_UI_DEP) validate-go-version
	@[ -f .downloaded_assets ] || $(MAKE) placeholders
	GOOS=darwin GOARCH=amd64 $(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	GOOS=darwin GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client

.PHONY: macos-arm64
macos-arm64: clean $(_UI_DEP) validate-go-version
	@[ -f .downloaded_assets ] || $(MAKE) placeholders
	GOOS=darwin GOARCH=arm64 $(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	GOOS=darwin GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client

.PHONY: linux-amd64
linux-amd64: clean $(_UI_DEP) validate-go-version
	@[ -f .downloaded_assets ] || $(MAKE) placeholders
	GOOS=linux GOARCH=amd64 $(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	GOOS=linux GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client

.PHONY: linux-arm64
linux-arm64: clean $(_UI_DEP) validate-go-version
	@[ -f .downloaded_assets ] || $(MAKE) placeholders
	GOOS=linux GOARCH=arm64 $(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	GOOS=linux GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client

.PHONY: windows-amd64
windows-amd64: clean $(_UI_DEP) validate-go-version
	@[ -f .downloaded_assets ] || $(MAKE) placeholders
	GOOS=windows GOARCH=amd64 $(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server$(ARTIFACT_SUFFIX).exe ./server
	GOOS=windows GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client$(ARTIFACT_SUFFIX).exe ./client

# ─── Android Targets ──────────────────────────────────────────────────────────

.PHONY: android-arm64
## Build Android ARM64 implant (most modern Android devices)
android-arm64: validate-go-version
	GOOS=android GOARCH=arm64 CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath \
		-tags "android" \
		$(LDFLAGS) \
		-o phantom_android_arm64 \
		./implant
	@echo "[*] Android ARM64 implant: phantom_android_arm64"
	@echo "[*] Deploy: adb push phantom_android_arm64 /data/local/tmp/ && adb shell chmod +x /data/local/tmp/phantom_android_arm64"

.PHONY: android-arm
## Build Android ARM implant (older Android devices)
android-arm: validate-go-version
	GOOS=android GOARCH=arm CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath \
		-tags "android" \
		$(LDFLAGS) \
		-o phantom_android_arm \
		./implant
	@echo "[*] Android ARM implant: phantom_android_arm"

.PHONY: android-amd64
## Build Android x86_64 implant (emulators)
android-amd64: validate-go-version
	GOOS=android GOARCH=amd64 CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath \
		-tags "android" \
		$(LDFLAGS) \
		-o phantom_android_amd64 \
		./implant
	@echo "[*] Android x86_64 implant (emulator): phantom_android_amd64"

.PHONY: android-all
## Build all Android implant variants
android-all: android-arm64 android-arm android-amd64
	@echo "[*] All Android implants built"

.PHONY: android-apk
## Package Android implant into APK
android-apk: android-arm64
	@bash build/android/build_apk.sh phantom_android_arm64
	@echo "[*] APK built: phantom_android.apk"

.PHONY: clients
clients: clean .downloaded_assets validate-go-version
	GOOS=darwin GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_macos-amd64$(ARTIFACT_SUFFIX) ./client
	GOOS=darwin GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_macos-arm64$(ARTIFACT_SUFFIX) ./client
	GOOS=linux GOARCH=386 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_linux-386$(ARTIFACT_SUFFIX) ./client
	GOOS=linux GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_linux-amd64$(ARTIFACT_SUFFIX) ./client
	GOOS=linux GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_linux-arm64$(ARTIFACT_SUFFIX) ./client
	GOOS=windows GOARCH=386 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_windows-386$(ARTIFACT_SUFFIX).exe ./client
	GOOS=windows GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_windows-amd64$(ARTIFACT_SUFFIX).exe ./client
	GOOS=windows GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_windows-arm64$(ARTIFACT_SUFFIX).exe ./client
	GOOS=freebsd GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_freebsd-amd64$(ARTIFACT_SUFFIX) ./client
	GOOS=freebsd GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),client $(LDFLAGS) -o sudosoc-client_freebsd-arm64$(ARTIFACT_SUFFIX) ./client

.PHONY: servers
servers: clean .downloaded_assets validate-go-version
	GOOS=windows GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_windows-amd64$(ARTIFACT_SUFFIX).exe ./server
	GOOS=windows GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_windows-arm64$(ARTIFACT_SUFFIX).exe ./server
	GOOS=linux GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_linux-amd64$(ARTIFACT_SUFFIX) ./server
	GOOS=linux GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_linux-arm64$(ARTIFACT_SUFFIX) ./server
	GOOS=darwin GOARCH=arm64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_darwin-arm64$(ARTIFACT_SUFFIX) ./server
	GOOS=darwin GOARCH=amd64 $(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath $(TAGS),server $(LDFLAGS) -o sudosoc-server_darwin-amd64$(ARTIFACT_SUFFIX) ./server

## Regenerate protobuf .pb.go files from .proto sources.
## Auto-installs protoc-gen-go and protoc-gen-go-grpc if not found.
## Run this if you see protobuf panic/corruption errors at startup.
.PHONY: pb
pb:
	@echo "[*] Checking protoc plugins..."
	@export PATH=$$PATH:$$(go env GOPATH)/bin; \
	if ! command -v protoc-gen-go >/dev/null 2>&1; then \
		echo "[*] Installing protoc-gen-go..."; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11; \
	fi; \
	if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then \
		echo "[*] Installing protoc-gen-go-grpc..."; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0; \
	fi
	@echo "[*] Regenerating .pb.go files..."
	PATH=$$PATH:$$(go env GOPATH)/bin protoc -I protobuf/ protobuf/commonpb/common.proto --go_out=paths=source_relative:protobuf/
	PATH=$$PATH:$$(go env GOPATH)/bin protoc -I protobuf/ protobuf/sudosocpb/sudosoc.proto --go_out=paths=source_relative:protobuf/
	PATH=$$PATH:$$(go env GOPATH)/bin protoc -I protobuf/ protobuf/clientpb/client.proto --go_out=paths=source_relative:protobuf/
	PATH=$$PATH:$$(go env GOPATH)/bin protoc -I protobuf/ protobuf/dnspb/dns.proto --go_out=paths=source_relative:protobuf/
	PATH=$$PATH:$$(go env GOPATH)/bin protoc -I protobuf/ protobuf/rpcpb/services.proto --go_out=paths=source_relative:protobuf/ --go-grpc_out=protobuf/ --go-grpc_opt=paths=source_relative
	@echo "[+] Protobuf regeneration complete."
	@echo "    Run 'make server-only' to rebuild the server."

.PHONY: debug
debug: clean
	$(ENV) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -mod=vendor $(TAGS),server $(LDFLAGS_DEBUG) -o sudosoc-server$(ARTIFACT_SUFFIX) ./server
	$(ENV) CGO_ENABLED=0 $(GO) build -mod=vendor $(TAGS),client $(LDFLAGS_DEBUG) -o sudosoc-client$(ARTIFACT_SUFFIX) ./client

validate-go-version:
	@if [ $(GO_MAJOR_VERSION) -gt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MIN_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MIN_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi

.PHONY: clean-all
clean-all: clean
	rm -rf ./server/assets/fs/darwin/amd64
	rm -rf ./server/assets/fs/darwin/arm64
	rm -rf ./server/assets/fs/windows/amd64
	rm -rf ./server/assets/fs/linux/amd64
	rm -f ./server/assets/fs/*.zip
	rm -f ./.downloaded_assets

.PHONY: clean
clean:
	rm -f sudosoc-client sudosoc-client_* sudosoc-server sudosoc-server_* sliver-*.exe
	@echo "[-] Binaries cleaned (run 'make clean-ui' to also remove Web UI dist)"

.downloaded_assets:
	$(ENV) $(GO) run -mod=vendor ./util/cmd/assets
	touch ./.downloaded_assets


#
# >>> WINDOWS <<<
#
else

SHELL := cmd.exe
.SHELLFLAGS := /C

GO_VERSION := $(patsubst go%,%,$(strip $(shell $(GO) env GOVERSION)))
GO_MAJOR_VERSION := $(word 1,$(subst ., ,$(GO_VERSION)))
GO_MINOR_VERSION := $(word 2,$(subst ., ,$(GO_VERSION)))

LDFLAGS = -ldflags "-s -w -X $(SLIVER_UPDATE_PKG).SliverPublicKey=$(SLIVER_PUBLIC_KEY) -X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) -X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"

LDFLAGS_DEBUG = -ldflags "-X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) -X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"

COMMA := ,

ifeq ($(MAKECMDGOALS), linux)
	LDFLAGS = -ldflags "-s -w -extldflags '-static' -X $(CLIENT_ASSETS_PKG).DefaultArmoryPublicKey=$(ARMORY_PUBLIC_KEY) -X $(CLIENT_ASSETS_PKG).DefaultArmoryRepoURL=$(ARMORY_REPO_URL)"
endif

define windows_exec
$(strip $(foreach envvar,$(1),set "$(envvar)" && ))$(2)
endef

define windows_go_build
$(call windows_exec,$(ENV) GOOS=$(1) GOARCH=$(2) CGO_ENABLED=$(3),"$(GO)" build $(4) $(TAGS)$(COMMA)$(5) $(6) -o $(7) ./$(5))
endef

## Build the React Web UI (Windows)
.PHONY: ui
ui:
	cd webui && npm install && npm run build
	@echo [+] Web UI built

## Download Go toolchains + Garble + Zig for implant generation (Windows, ~500 MB)
.PHONY: assets
assets:
	$(call windows_exec,$(ENV),"$(GO)" run -mod=vendor ./util/cmd/assets)
	@type NUL > .downloaded_assets
	@echo [+] Assets downloaded

## Create placeholder assets for quick compilation without toolchain download (Windows)
.PHONY: placeholders
placeholders:
	@echo [*] Creating placeholder assets...
	-@if not exist server\assets\fs\linux\amd64   mkdir server\assets\fs\linux\amd64
	-@if not exist server\assets\fs\linux\arm64   mkdir server\assets\fs\linux\arm64
	-@if not exist server\assets\fs\darwin\amd64  mkdir server\assets\fs\darwin\amd64
	-@if not exist server\assets\fs\darwin\arm64  mkdir server\assets\fs\darwin\arm64
	-@if not exist server\assets\fs\windows\amd64 mkdir server\assets\fs\windows\amd64
	@if not exist server\assets\fs\linux\amd64\placeholder.txt   echo placeholder>server\assets\fs\linux\amd64\placeholder.txt
	@if not exist server\assets\fs\linux\arm64\placeholder.txt   echo placeholder>server\assets\fs\linux\arm64\placeholder.txt
	@if not exist server\assets\fs\darwin\amd64\placeholder.txt  echo placeholder>server\assets\fs\darwin\amd64\placeholder.txt
	@if not exist server\assets\fs\darwin\arm64\placeholder.txt  echo placeholder>server\assets\fs\darwin\arm64\placeholder.txt
	@if not exist server\assets\fs\windows\amd64\placeholder.txt echo placeholder>server\assets\fs\windows\amd64\placeholder.txt
	@if not exist server\assets\fs\placeholder.zip cd server\assets\fs && zip -q placeholder.zip empty.txt
	@type NUL > .downloaded_assets
	@echo [+] Placeholder assets created. Run 'make assets' later for full implant generation.

## Rebuild only the Go binaries — fast path when UI is already built (Windows)
.PHONY: server-only
server-only:
	$(call windows_go_build,$(GOOS),$(GOARCH),$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,$(GOOS),$(GOARCH),0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))
	@echo [+] Go binaries rebuilt

.PHONY: default
default: clean validate-go-version ui
	@if not exist .downloaded_assets $(MAKE) placeholders
	$(call windows_go_build,$(GOOS),$(GOARCH),$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,$(GOOS),$(GOARCH),0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))
	@echo [+] Build complete

.PHONY: client
client: clean .downloaded_assets validate-go-version
	$(call windows_go_build,$(GOOS),$(GOARCH),0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client)

.PHONY: macos-amd64
macos-amd64: clean ui .downloaded_assets validate-go-version
	$(call windows_go_build,darwin,amd64,$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,darwin,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))

.PHONY: macos-arm64
macos-arm64: clean ui .downloaded_assets validate-go-version
	$(call windows_go_build,darwin,arm64,$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,darwin,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))

.PHONY: linux-amd64
linux-amd64: clean ui .downloaded_assets validate-go-version
	$(call windows_go_build,linux,amd64,$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))

.PHONY: linux-arm64
linux-arm64: clean ui .downloaded_assets validate-go-version
	$(call windows_go_build,linux,arm64,$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX))

.PHONY: windows-amd64
windows-amd64: clean ui .downloaded_assets validate-go-version
	$(call windows_go_build,windows,amd64,$(CGO_ENABLED),-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,windows,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client$(ARTIFACT_SUFFIX).exe)

.PHONY: clients
clients: clean .downloaded_assets validate-go-version
	$(call windows_go_build,darwin,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_macos-amd64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,darwin,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_macos-arm64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,386,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_linux-386$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_linux-amd64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_linux-arm64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,windows,386,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_windows-386$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,windows,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_windows-amd64$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,windows,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_windows-arm64$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,freebsd,amd64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_freebsd-amd64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,freebsd,arm64,0,-mod=vendor -trimpath,client,$(LDFLAGS),sudosoc-client_freebsd-arm64$(ARTIFACT_SUFFIX))

.PHONY: servers
servers: clean .downloaded_assets validate-go-version
	$(call windows_go_build,windows,amd64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_windows-amd64$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,windows,arm64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_windows-arm64$(ARTIFACT_SUFFIX).exe)
	$(call windows_go_build,linux,amd64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_linux-amd64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,linux,arm64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_linux-arm64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,darwin,arm64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_darwin-arm64$(ARTIFACT_SUFFIX))
	$(call windows_go_build,darwin,amd64,0,-mod=vendor -trimpath,server,$(LDFLAGS),sudosoc-server_darwin-amd64$(ARTIFACT_SUFFIX))

.PHONY: pb
pb: validate-pb-compilers
	protoc -I protobuf/ protobuf/commonpb/common.proto --go_out=paths=source_relative:protobuf/
	protoc -I protobuf/ protobuf/sudosocpb/sudosoc.proto --go_out=paths=source_relative:protobuf/
	protoc -I protobuf/ protobuf/clientpb/client.proto --go_out=paths=source_relative:protobuf/
	protoc -I protobuf/ protobuf/dnspb/dns.proto --go_out=paths=source_relative:protobuf/
	protoc -I protobuf/ protobuf/rpcpb/services.proto --go_out=paths=source_relative:protobuf/ --go-grpc_out=protobuf/ --go-grpc_opt=paths=source_relative

.PHONY: debug
debug: clean
	$(call windows_go_build,$(GOOS),$(GOARCH),$(CGO_ENABLED),-mod=vendor,server,$(LDFLAGS_DEBUG),sudosoc-server$(ARTIFACT_SUFFIX))
	$(call windows_go_build,$(GOOS),$(GOARCH),0,-mod=vendor,client,$(LDFLAGS_DEBUG),sudosoc-client$(ARTIFACT_SUFFIX))

.PHONY: validate-pb-compilers
validate-pb-compilers:
	@for %%P in ($(PB_COMPILERS)) do @where.exe %%P >NUL || (echo Missing protobuf util %%P in PATH & exit /b 1)

validate-go-version:
	@if $(GO_MAJOR_VERSION) GTR $(MIN_SUPPORTED_GO_MAJOR_VERSION) (exit /b 0) else if $(GO_MAJOR_VERSION) LSS $(MIN_SUPPORTED_GO_MAJOR_VERSION) (echo $(GO_VERSION_VALIDATION_ERR_MSG) & exit /b 1) else if $(GO_MINOR_VERSION) LSS $(MIN_SUPPORTED_GO_MINOR_VERSION) (echo $(GO_VERSION_VALIDATION_ERR_MSG) & exit /b 1)

.PHONY: clean-all
clean-all: clean
	-rmdir /S /Q server\assets\fs\darwin\amd64
	-rmdir /S /Q server\assets\fs\darwin\arm64
	-rmdir /S /Q server\assets\fs\windows\amd64
	-rmdir /S /Q server\assets\fs\linux\amd64
	-del /Q /F server\assets\fs\*.zip 2>NUL
	-del /Q /F .downloaded_assets 2>NUL

.PHONY: clean
clean:
	-del /Q /F sudosoc-client sudosoc-client_* sudosoc-server sudosoc-server_* sliver-*.exe 2>NUL

## Remove compiled Web UI (Windows)
.PHONY: clean-ui
clean-ui:
	-rmdir /S /Q server\web\dist 2>NUL
	-mkdir server\web\dist 2>NUL
	@echo [-] Web UI dist cleaned

.downloaded_assets:
	$(call windows_exec,$(ENV),"$(GO)" run -mod=vendor ./util/cmd/assets)
	@type NUL > .downloaded_assets

endif
