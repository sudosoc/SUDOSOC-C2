#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# fix_proto.sh — Regenerate corrupted protobuf .pb.go files
#
# The rebranding script corrupted the binary rawDesc inside the .pb.go files
# by doing text replacement inside the binary proto descriptor bytes.
# This script regenerates them cleanly from the .proto source files.
#
# Usage:
#   chmod +x fix_proto.sh
#   ./fix_proto.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[!]${NC} $*"; exit 1; }

# ── 0. Verify we're in the project root ──────────────────────────────────────
[[ -f "go.mod" ]] || error "Run this script from the SUDOSOC-C2 project root."
MODULE=$(head -1 go.mod | awk '{print $2}')
info "Project: $MODULE"

# ── 1. Install protoc ─────────────────────────────────────────────────────────
if ! command -v protoc &>/dev/null; then
    warn "protoc not found — installing via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y protobuf-compiler
fi
PROTOC_VER=$(protoc --version)
success "protoc: $PROTOC_VER"

# ── 2. Install protoc-gen-go plugins (matching vendored protobuf version) ─────
GOPATH_BIN=$(go env GOPATH)/bin
export PATH=$PATH:$GOPATH_BIN

PROTOBUF_VER=$(grep 'google.golang.org/protobuf ' go.mod | head -1 | awk '{print $2}')
GRPC_VER=$(grep 'google.golang.org/grpc ' go.mod | head -1 | awk '{print $2}')

info "Installing protoc-gen-go @ $PROTOBUF_VER ..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_VER}

info "Installing protoc-gen-go-grpc ..."
# Use a stable known-good version compatible with grpc v1.x
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

success "protoc-gen-go: $(protoc-gen-go --version 2>/dev/null || echo 'ok')"

# ── 3. Back up existing .pb.go files ─────────────────────────────────────────
BACKUP_DIR=".proto_backup_$(date +%Y%m%d_%H%M%S)"
info "Backing up existing .pb.go files → $BACKUP_DIR/"
mkdir -p "$BACKUP_DIR"
find protobuf -name "*.pb.go" | while read f; do
    d="$BACKUP_DIR/$(dirname $f)"
    mkdir -p "$d"
    cp "$f" "$d/"
done
success "Backup created."

# ── 4. Regenerate each proto file ─────────────────────────────────────────────
info "Regenerating protobuf Go files..."

PROTO_OUT="--go_out=paths=source_relative:protobuf"
GRPC_OUT="--go-grpc_out=paths=source_relative:protobuf"
PROTO_INC="-I protobuf"

# commonpb
info "  commonpb/common.proto"
protoc $PROTO_INC protobuf/commonpb/common.proto $PROTO_OUT

# sudosocpb (main implant messages)
info "  sudosocpb/sudosoc.proto"
protoc $PROTO_INC protobuf/sudosocpb/sudosoc.proto $PROTO_OUT

# clientpb
info "  clientpb/client.proto"
protoc $PROTO_INC protobuf/clientpb/client.proto $PROTO_OUT

# dnspb
info "  dnspb/dns.proto"
protoc $PROTO_INC protobuf/dnspb/dns.proto $PROTO_OUT

# rpcpb (gRPC service)
info "  rpcpb/services.proto"
protoc $PROTO_INC protobuf/rpcpb/services.proto \
    $PROTO_OUT \
    $GRPC_OUT

success "All .pb.go files regenerated."

# ── 5. Fix import paths in regenerated files ──────────────────────────────────
# protoc uses the go_package option from the .proto file, so imports should
# already use github.com/sudosoc/SUDOSOC-C2/... — verify:
info "Verifying import paths in regenerated files..."
BAD=$(grep -rl 'bishopfox\|BishopFox\|moloch' protobuf/ 2>/dev/null || true)
if [[ -n "$BAD" ]]; then
    warn "Found stale import references in:"
    echo "$BAD"
    warn "You may need to update these manually."
else
    success "Import paths look clean."
fi

# ── 6. Verify the fix compiled ────────────────────────────────────────────────
info "Running go build check on protobuf packages..."
if go build -mod=vendor ./protobuf/... 2>&1; then
    success "Protobuf packages compile cleanly."
else
    warn "Build still failing. Check output above."
    warn "Backup available at: $BACKUP_DIR/"
    exit 1
fi

# ── 7. Rebuild server ─────────────────────────────────────────────────────────
info "Rebuilding server & client..."
make server-only

success "═══════════════════════════════════════════════"
success "  Fix complete! Run:  ./sudosoc-server --ui    "
success "═══════════════════════════════════════════════"
