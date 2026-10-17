#!/bin/bash
# Builds the menu-bar app: build/macos/TierfsMenu.app (ad-hoc signed; it only talks to tierfsd's control socket, so it needs no entitlements).
set -euo pipefail
cd "$(dirname "$0")/.."
APP=build/macos/TierfsMenu.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O -parse-as-library -o "$APP/Contents/MacOS/TierfsMenu" macos/TierfsControl.swift macos/TierfsMenu.swift -framework AppKit
cat > "$APP/Contents/Info.plist" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>local.tierfs.menu</string>
  <key>CFBundleName</key><string>TierfsMenu</string>
  <key>CFBundleExecutable</key><string>TierfsMenu</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
P
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --sign - "$APP" 2>/dev/null
echo "built $APP"
