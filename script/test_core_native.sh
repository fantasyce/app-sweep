#!/bin/bash
# Compile only the shared backend and its native checks. No app install or UI.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
: "${APP_SWEEP_TEST_WORK_ROOT:?Set a dedicated task-owned build directory}"
: "${APP_SWEEP_FIXTURES:?Set a dedicated AppSweepAcceptance directory}"
: "${APP_SWEEP_SDK:?Set the macOS SDK path}"
test "$APP_SWEEP_TEST_WORK_ROOT" != / && test "$APP_SWEEP_TEST_WORK_ROOT" != "$HOME"
mkdir -p "$APP_SWEEP_TEST_WORK_ROOT/package/Sources"
cat > "$APP_SWEEP_TEST_WORK_ROOT/package/Package.swift" <<'SWIFT'
// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "CoreNativeChecks", platforms: [.macOS(.v12)], products: [.executable(name: "app-sweep", targets: ["AppSweepCLI"])], targets: [
    .target(name: "CFSafety", linkerSettings: [.linkedLibrary("bsm")]),
    .target(name: "AppSweepCore", dependencies: ["CFSafety"], swiftSettings: [.unsafeFlags(["-enable-testing"])]),
    .executableTarget(name: "CoreNativeChecks", dependencies: ["AppSweepCore"]),
    .executableTarget(name: "AppSweepCLI", dependencies: ["AppSweepCore"], swiftSettings: [.unsafeFlags(["-parse-as-library"])])
])
SWIFT
# Keep the generated package disposable; source and checks remain in this repo.
for target in CFSafety AppSweepCore AppSweepCLI; do
    test -e "$APP_SWEEP_TEST_WORK_ROOT/package/Sources/$target" || ln -s "$repo/Sources/$target" "$APP_SWEEP_TEST_WORK_ROOT/package/Sources/$target"
done
test -e "$APP_SWEEP_TEST_WORK_ROOT/package/Sources/CoreNativeChecks" || ln -s "$repo/Tests/NativeCoreChecks" "$APP_SWEEP_TEST_WORK_ROOT/package/Sources/CoreNativeChecks"
product=CoreNativeChecks
if [ "${1:-}" = --build-cli ]; then product=app-sweep; fi
swift build --build-system native --package-path "$APP_SWEEP_TEST_WORK_ROOT/package" --scratch-path "$APP_SWEEP_TEST_WORK_ROOT/build" --sdk "$APP_SWEEP_SDK" --product "$product" -j 2
if [ "$product" = app-sweep ]; then exit 0; fi
"$APP_SWEEP_TEST_WORK_ROOT/build/debug/CoreNativeChecks" "$@"
