#!/bin/bash
set -euo pipefail
# Explicit local opt-in or the disposable ARM macOS guest only.
case "${APP_SWEEP_BUILD_HOST:-guest}" in
  local) ;;
  guest) case "$(/usr/sbin/sysctl -n hw.model)" in VirtualMac*) ;; *) echo '请显式选择本机构建或在隔离 ARM macOS 虚拟机中构建。' >&2; exit 2;; esac ;;
  *) exit 2 ;;
esac
[ "$(uname -m)" = arm64 ] || exit 2
[ "$(id -u)" != 0 ] || exit 2
# Delivery must never silently become a new ad-hoc identity on every upgrade.
# Development packages are explicitly marked and are not delivery acceptance.
BUILD_MODE=${APP_SWEEP_BUILD_MODE:-delivery}
SIGNING_IDENTITY=${APP_SWEEP_SIGNING_IDENTITY:-}
case "$BUILD_MODE" in
  delivery)
    case "$SIGNING_IDENTITY" in
      ''|-|*[!0-9A-Fa-f]*) echo '交付构建需要有效的稳定签名身份（证书 SHA-1）。' >&2; exit 2 ;;
    esac
    [ "${#SIGNING_IDENTITY}" = 40 ] || { echo '交付构建需要有效的稳定签名身份（证书 SHA-1）。' >&2; exit 2; }
    /usr/bin/security find-identity -v -p codesigning | /usr/bin/grep -qiF "$SIGNING_IDENTITY" || {
      echo '交付构建需要有效的稳定签名身份；当前钥匙串不可用。' >&2; exit 2;
    }
    ;;
  development|delivery-adhoc) SIGNING_IDENTITY=- ;;
  *) echo '构建模式无效；请选择 delivery、delivery-adhoc 或 development。' >&2; exit 2 ;;
esac
SOURCE=$(cd "$(dirname "$0")/.." && pwd)
TASK="${APP_SWEEP_BUILD_ROOT:-$HOME/AppSweepAcceptance}"
SDK=${APP_SWEEP_SDK:?Set the isolated macOS SDK path}
for p in "$TASK" "$TASK/output" "$TASK/build"; do [ ! -L "$p" ] || exit 2; done
mkdir -p "$TASK/output" "$TASK/build"
OUTPUT=$(mktemp -d "$TASK/output/build-$(date +%Y%m%d-%H%M%S)-XXXXXX")
ARCHES=(arm64 x86_64)
[ "${APP_SWEEP_BUILD_HOST:-guest}" != local ] || ARCHES=(arm64)
for arch in "${ARCHES[@]}"; do
  swift build --build-system native --package-path "$SOURCE" -c release -j 2 --scratch-path "$TASK/build/$arch" --triple "$arch-apple-macosx12.0" --sdk "$SDK"
done
ARM="$TASK/build/arm64/arm64-apple-macosx/release"
INTEL="$TASK/build/x86_64/x86_64-apple-macosx/release"
# SwiftPM directory names can include the deployment target; ask SwiftPM for exact paths.
ARM=$(swift build --build-system native --package-path "$SOURCE" -c release --scratch-path "$TASK/build/arm64" --triple arm64-apple-macosx12.0 --sdk "$SDK" --show-bin-path)
if [ "${#ARCHES[@]}" = 2 ]; then INTEL=$(swift build --build-system native --package-path "$SOURCE" -c release --scratch-path "$TASK/build/x86_64" --triple x86_64-apple-macosx12.0 --sdk "$SDK" --show-bin-path); fi
APP="$OUTPUT/App Sweep.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/HelperTools"
for product in AppSweepApp app-sweep AppSweepSystemService AppSweepServiceInstaller; do
  case "$product" in AppSweepApp|app-sweep) destination="$APP/Contents/MacOS/$product" ;; *) destination="$APP/Contents/Library/HelperTools/$product" ;; esac
  if [ "${#ARCHES[@]}" = 2 ]; then /usr/bin/lipo -create "$ARM/$product" "$INTEL/$product" -output "$destination"
  else cp "$ARM/$product" "$destination"; fi
done
cp "$SOURCE/Sources/AppSweepAppV2/Resources/Yozai-Regular.ttf" "$APP/Contents/Resources/"
cp "$SOURCE/Sources/AppSweepAppV2/Resources/OFL-Yozai.txt" "$APP/Contents/Resources/"
cp "$SOURCE/LICENSE" "$APP/Contents/Resources/LICENSE-AppSweep.txt"
cp "$SOURCE/Assets/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>App Sweep</string>
<key>CFBundleDisplayName</key><string>App Sweep</string>
<key>CFBundleIdentifier</key><string>org.appsweep.app</string>
<key>CFBundleExecutable</key><string>AppSweepApp</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleDevelopmentRegion</key><string>zh-Hans</string>
<key>CFBundleLocalizations</key><array><string>zh-Hans</string></array>
<key>CFBundleShortVersionString</key><string>2.1.0</string>
<key>CFBundleVersion</key><string>52</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSAppDataUsageDescription</key><string>App Sweep 需要核对其他应用的资料归属，以扫描垃圾和准备卸载计划。未授权的内容会保留；不会立即清理文件。</string>
</dict></plist>
PLIST
/usr/libexec/PlistBuddy -c "Add :AppSweepBuildMode string $BUILD_MODE" "$APP/Contents/Info.plist"
# Remove local source/object paths from debug symbol records before signing.
for binary in "$APP/Contents/MacOS/AppSweepApp" "$APP/Contents/MacOS/app-sweep" "$APP/Contents/Library/HelperTools/AppSweepSystemService" "$APP/Contents/Library/HelperTools/AppSweepServiceInstaller"; do
  /usr/bin/strip -S "$binary"
done
/usr/bin/codesign --force --options runtime --sign "$SIGNING_IDENTITY" --identifier org.appsweep.cli "$APP/Contents/MacOS/app-sweep"
/usr/bin/codesign --force --options runtime --sign "$SIGNING_IDENTITY" --identifier org.appsweep.system-service "$APP/Contents/Library/HelperTools/AppSweepSystemService"
/usr/bin/codesign --force --options runtime --sign "$SIGNING_IDENTITY" --identifier org.appsweep.service-installer "$APP/Contents/Library/HelperTools/AppSweepServiceInstaller"
/usr/bin/codesign --force --options runtime --sign "$SIGNING_IDENTITY" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
/usr/bin/lipo -info "$APP/Contents/MacOS/AppSweepApp" > "$OUTPUT/architectures.txt"
/usr/bin/lipo -info "$APP/Contents/MacOS/app-sweep" >> "$OUTPUT/architectures.txt"
# The configuration is deliberately outside the signed app: embedding a file
# containing its own final CDHash would create a circular signing dependency.
# This is an uninstalled staging payload; the reviewed Installer lifecycle is
# required before any of these files may be written to the system locations.
PAYLOAD="$OUTPUT/SystemServicePayload"
SUPPORT="$PAYLOAD/Library/Application Support/App Sweep"
SERVICE="$SUPPORT/Service"
mkdir -p "$SERVICE" "$SUPPORT/Recovery.noindex" "$PAYLOAD/Library/LaunchDaemons"
chmod 755 "$SUPPORT" "$SERVICE"
chmod 700 "$SUPPORT/Recovery.noindex"
cp "$APP/Contents/Library/HelperTools/AppSweepSystemService" "$SERVICE/AppSweepSystemService"
chmod 755 "$SERVICE/AppSweepSystemService"
cp "$SOURCE/script/system-service/org.appsweep.system-service.plist" "$PAYLOAD/Library/LaunchDaemons/"
chmod 644 "$PAYLOAD/Library/LaunchDaemons/org.appsweep.system-service.plist"
code_hash() {
  /usr/bin/codesign -d --verbose=4 --arch "$1" "$2" 2>&1 | /usr/bin/awk '/^CDHash=/ { sub(/^CDHash=/, ""); print; found++ } END { if (found != 1) exit 1 }'
}
client_hashes=()
service_hashes=()
for arch in "${ARCHES[@]}"; do
  client_hashes+=("$(code_hash "$arch" "$APP/Contents/MacOS/AppSweepApp")")
  client_hashes+=("$(code_hash "$arch" "$APP/Contents/MacOS/app-sweep")")
  service_hashes+=("$(code_hash "$arch" "$APP/Contents/Library/HelperTools/AppSweepSystemService")")
done
build_tag="2.1.0-local-$(date -u +%Y%m%dT%H%M%SZ)"
/usr/bin/python3 - "$SERVICE/config.json" "$build_tag" "${#ARCHES[@]}" "${client_hashes[@]}" "${service_hashes[@]}" <<'PYTHON'
import json, re, sys
path, build, count, *hashes = sys.argv[1:]
count = int(count)
assert count in (1, 2)
assert len(hashes) == count * 3 and all(re.fullmatch(r'[0-9a-f]{40}', value) for value in hashes)
clients, services = sorted(set(hashes[:count*2])), sorted(set(hashes[count*2:]))
assert len(clients) == count*2 and len(services) == count
pins = dict(schemaVersion=1, serviceBuild=build, clientCodeHashes=clients, serviceCodeHashes=services)
with open(path, 'x', encoding='utf-8') as output:
    json.dump(pins, output, sort_keys=True, separators=(',', ':'))
PYTHON
chmod 644 "$SERVICE/config.json"
/usr/bin/lipo -info "$APP/Contents/Library/HelperTools/AppSweepSystemService" >> "$OUTPUT/architectures.txt"
/usr/bin/lipo -info "$APP/Contents/Library/HelperTools/AppSweepServiceInstaller" >> "$OUTPUT/architectures.txt"
# A script-only package delegates all fixed-path changes to the transaction
# engine. Installer must not copy files over a live or partially upgraded daemon.
INSTALL_SCRIPTS="$OUTPUT/ServiceInstallerScripts"
mkdir -m 755 "$INSTALL_SCRIPTS"
cp -R "$PAYLOAD" "$INSTALL_SCRIPTS/Payload"
cp "$APP/Contents/Library/HelperTools/AppSweepServiceInstaller" "$INSTALL_SCRIPTS/AppSweepServiceInstaller"
chmod 755 "$INSTALL_SCRIPTS/AppSweepServiceInstaller"
cp "$SOURCE/script/system-service/postinstall" "$INSTALL_SCRIPTS/postinstall"
chmod 755 "$INSTALL_SCRIPTS/postinstall"
/usr/bin/pkgbuild --nopayload --scripts "$INSTALL_SCRIPTS" --identifier org.appsweep.system-service.installer --version 2.1.0 --install-location / "$OUTPUT/App-Sweep-System-Service-2.1.0.pkg"
/usr/bin/python3 "$SOURCE/Tests/Infrastructure/verify_system_service_payload.py" "$OUTPUT" "${ARCHES[@]}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$PAYLOAD" "$OUTPUT/System-Service-Payload.zip"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP" "$OUTPUT/App-Sweep-2.1.0.zip"
/usr/bin/shasum -a 256 "$OUTPUT/App-Sweep-2.1.0.zip" "$OUTPUT/System-Service-Payload.zip" "$OUTPUT/App-Sweep-System-Service-2.1.0.pkg" > "$OUTPUT/SHA256.txt"
printf '%s\n' "$OUTPUT" > "$TASK/latest-output.txt"
echo "构件已保存：${OUTPUT}；系统服务素材尚未安装，尚未启动产品。"
