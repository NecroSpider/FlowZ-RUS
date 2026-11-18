#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${1:-$(node -p "require('./package.json').version")}"
TEMP_DIR=""
trap '[ -z "$TEMP_DIR" ] || rm -rf "$TEMP_DIR"' EXIT

for ARCH in arm64 x64; do
  case "$ARCH" in arm64) WANT=arm64 ;; x64) WANT=x86_64 ;; esac
  APP_PATH=""
  for CAND in "dist-package/mac-${ARCH}/FlowZ.app" "dist-package/mac/FlowZ.app"; do
    [ -d "$CAND" ] || continue
    for EXE in "$CAND"/Contents/MacOS/*; do
      if lipo -archs "$EXE" 2>/dev/null | tr ' ' '\n' | grep -qx "$WANT"; then
        APP_PATH="$CAND"
        break 2
      fi
    done
  done
  if [ -z "$APP_PATH" ]; then
    echo "FlowZ.app for ${ARCH} (${WANT}) not found" >&2
    exit 1
  fi

  codesign --force --deep --sign - "$APP_PATH"
  codesign --verify --deep --strict "$APP_PATH"
  # Signing must not change the core trusted by the privileged helper.
  node - "$APP_PATH" "$ARCH" <<'NODE'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const [app, arch] = process.argv.slice(2);
const manifest = require(path.resolve('src/shared/core-manifest.json'));
const core = path.join(app, 'Contents/Resources/mac/sing-box');
const digest = crypto.createHash('sha256').update(fs.readFileSync(core)).digest('hex');
if (digest !== manifest.coreBinarySha256[`mac-${arch}`]) {
  throw new Error(`Signed mac-${arch} bundle has an untrusted sing-box binary`);
}
NODE

  TEMP_DIR="$(mktemp -d)"
  cp -R "$APP_PATH" "$TEMP_DIR/"
  ln -s /Applications "$TEMP_DIR/Applications"
  cp build/macos-dmg-open-guide.txt "$TEMP_DIR/0 READ ME FIRST.txt"
  DMG_PATH="dist-package/FlowZ-${VERSION}-mac-${ARCH}.dmg"
  CREATED=0
  for ATTEMPT in 1 2 3; do
    # HFS+ avoids the intermittent APFS image creation failures on macOS runners.
    if hdiutil create -volname "FlowZ ${VERSION} (${ARCH})" -fs HFS+ \
      -srcfolder "$TEMP_DIR" -ov -format UDZO "$DMG_PATH"; then
      CREATED=1
      break
    fi
    echo "DMG creation failed for ${ARCH}, attempt ${ATTEMPT}/3" >&2
    sleep "$((ATTEMPT * 2))"
  done
  [ "$CREATED" = 1 ] || exit 1
  hdiutil imageinfo "$DMG_PATH" >/dev/null
  rm -rf "$TEMP_DIR"
  TEMP_DIR=""
  echo "Created: $DMG_PATH"
done
