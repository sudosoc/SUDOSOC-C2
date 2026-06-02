#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# fix_proto.sh — One-shot setup for a fresh SUDOSOC-C2 clone
#
# Fixes:
#   1. Corrupted protobuf rawDesc (from rebranding text-replacement)
#   2. Missing toolchain assets (creates placeholders for compile)
#   3. Missing Web UI (creates placeholder index.html for go:embed)
#
# After this script: ./sudosoc-server --ui  →  working binary + browser UI
# Run `make assets` separately for full implant generation support.
#
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: The implant source is EMBEDDED inside the server binary via
# //go:embed in implant/implant.go. This means:
#   - Any change to implant/sliver/** requires 'make server-only' to rebuild
#   - 'git pull' alone is NOT sufficient for implant source changes
#   - Always run: git pull && make server-only
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   chmod +x fix_proto.sh && ./fix_proto.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[!]${NC} $*"; exit 1; }

# ── 0. Verify project root ────────────────────────────────────────────────────
[[ -f "go.mod" ]] || error "Run from the SUDOSOC-C2 project root."
info "Project: $(head -1 go.mod | awk '{print $2}')"

# ── 1. Install protoc ─────────────────────────────────────────────────────────
if ! command -v protoc &>/dev/null; then
    warn "protoc not found — installing..."
    sudo apt-get update -qq && sudo apt-get install -y protobuf-compiler
fi
success "protoc: $(protoc --version)"

# ── 2. Install protoc-gen-go plugins ─────────────────────────────────────────
GOPATH_BIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOPATH_BIN"

PROTOBUF_VER=$(grep 'google.golang.org/protobuf ' go.mod | awk '{print $2}')
info "Installing protoc-gen-go @ $PROTOBUF_VER ..."
go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_VER}"
info "Installing protoc-gen-go-grpc ..."
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
success "protoc-gen-go: $(protoc-gen-go --version 2>/dev/null || echo installed)"

# ── 3. Remove android_types.go stub ──────────────────────────────────────────
# This stub is superseded by the properly generated sudosoc.pb.go after protoc
# regeneration. Keeping both causes redeclaration build errors.
if [[ -f "protobuf/sudosocpb/android_types.go" ]]; then
    info "Removing android_types.go stub (superseded by generated code)..."
    rm -f protobuf/sudosocpb/android_types.go
    success "Removed."
fi

# ── 4. Back up existing .pb.go files ─────────────────────────────────────────
BACKUP_DIR=".proto_backup_$(date +%Y%m%d_%H%M%S)"
info "Backing up existing .pb.go files → $BACKUP_DIR/"
mkdir -p "$BACKUP_DIR"
find protobuf -name "*.pb.go" 2>/dev/null | while read -r f; do
    d="$BACKUP_DIR/$(dirname "$f")"
    mkdir -p "$d"
    cp "$f" "$d/"
done
success "Backup created."

# ── 5. Regenerate .pb.go files ────────────────────────────────────────────────
info "Regenerating protobuf Go files..."
POUT="--go_out=paths=source_relative:protobuf"
GOUT="--go-grpc_out=paths=source_relative:protobuf"
INC="-I protobuf"

for proto in \
    "protobuf/commonpb/common.proto" \
    "protobuf/sudosocpb/sudosoc.proto" \
    "protobuf/clientpb/client.proto" \
    "protobuf/dnspb/dns.proto"; do
    info "  $proto"
    protoc $INC "$proto" $POUT
done

info "  protobuf/rpcpb/services.proto"
protoc $INC protobuf/rpcpb/services.proto $POUT $GOUT

success "All .pb.go files regenerated."

# ── 6. Verify import paths ────────────────────────────────────────────────────
info "Verifying import paths..."
BAD=$(grep -rl 'bishopfox\|BishopFox\|moloch' protobuf/ 2>/dev/null || true)
if [[ -n "$BAD" ]]; then
    warn "Stale imports found in: $BAD"
else
    success "Import paths clean."
fi

# ── 7. Create placeholder toolchain assets (if needed) ────────────────────────
if [[ ! -f ".downloaded_assets" ]]; then
    info "Creating placeholder toolchain assets (enables build without downloading ~500 MB)..."
    make placeholders
fi

# ── 8. Verify protobuf compiles ───────────────────────────────────────────────
info "Checking protobuf packages compile..."
if go build -mod=vendor ./protobuf/... 2>&1; then
    success "Protobuf packages: OK"
else
    warn "Protobuf still failing — check output above."
    warn "Backup at: $BACKUP_DIR/"
    exit 1
fi

# ── 9. Rebuild server + client ────────────────────────────────────────────────
info "Building server & client..."
make server-only

echo ""
success "══════════════════════════════════════════════════════"
success "  Setup complete!                                     "
success "                                                      "
success "  Start server:   ./sudosoc-server                    "
success "  With Web UI:    ./sudosoc-server --ui               "
success "  With TUI:       ./sudosoc-server --tui              "
success "  Browser:        http://localhost:8080               "
success "                                                      "
success "  For implant generation: make assets  (~500 MB)      "
success "══════════════════════════════════════════════════════"
