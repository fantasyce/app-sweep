#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/app-sweep-tests.XXXXXX")"
TEST_HOME="$TMP_DIR/home"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_HOME"
cd "$ROOT_DIR"

swift build --product app-sweep
BIN_DIR="$(swift build --show-bin-path)"
BIN="$BIN_DIR/app-sweep"
if [[ ! -x "$BIN" ]]; then
  BIN="$BIN_DIR/AppSweepCLI"
fi
if [[ ! -x "$BIN" ]]; then
  echo "app-sweep executable was not built" >&2
  exit 1
fi

make_app() {
  local path="$1"
  local bundle_id="$2"
  local name="$3"
  mkdir -p "$path/Contents"
  cat > "$path/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>$bundle_id</string>
  <key>CFBundleName</key>
  <string>$name</string>
  <key>CFBundleDisplayName</key>
  <string>$name</string>
  <key>CFBundleExecutable</key>
  <string>$name</string>
</dict>
</plist>
PLIST
}

run_cli() {
  HOME="$TEST_HOME" "$BIN" "$@"
}

SCAN_APP="$TMP_DIR/ScanTarget.app"
SCAN_JSON="$TMP_DIR/scan.json"
make_app "$SCAN_APP" "com.example.AppSweepScan" "ScanTarget"
run_cli scan "$SCAN_APP" --json "$SCAN_JSON" > "$TMP_DIR/scan.out" 2> "$TMP_DIR/scan.err"
/usr/bin/python3 - "$SCAN_JSON" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    report = json.load(f)

assert report["app"]["bundleIdentifier"] == "com.example.AppSweepScan"
assert report["app"]["displayName"] == "ScanTarget"
assert report["summary"]["existingCandidates"] >= 1
PY

APPLE_APP="$TMP_DIR/AppleTarget.app"
make_app "$APPLE_APP" "com.apple.AppSweepTest" "AppleTarget"
set +e
run_cli scan "$APPLE_APP" > "$TMP_DIR/apple.out" 2> "$TMP_DIR/apple.err"
APPLE_STATUS=$?
set -e
if [[ "$APPLE_STATUS" -ne 2 ]]; then
  echo "expected Apple bundle scan to exit 2, got $APPLE_STATUS" >&2
  exit 1
fi
if ! grep -q "Refusing to process Apple/system app" "$TMP_DIR/apple.err"; then
  echo "expected Apple bundle refusal message" >&2
  exit 1
fi

SYMLINK_TARGET="$TMP_DIR/target.txt"
SYMLINK_PATH="$TMP_DIR/linked-target"
SYMLINK_JSON="$TMP_DIR/trash-path.json"
printf "target" > "$SYMLINK_TARGET"
ln -s "$SYMLINK_TARGET" "$SYMLINK_PATH"
run_cli trash-path "$SYMLINK_PATH" --execute --trash-confirm --json "$SYMLINK_JSON" > "$TMP_DIR/symlink.out" 2> "$TMP_DIR/symlink.err"
if [[ "$(readlink "$SYMLINK_PATH")" != "$SYMLINK_TARGET" ]]; then
  echo "symlink was unexpectedly changed" >&2
  exit 1
fi
/usr/bin/python3 - "$SYMLINK_JSON" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    report = json.load(f)

candidate = report["candidate"]
assert candidate["action"] == "blocked"
assert candidate["confidence"] == "blocked"
assert candidate["status"] == "skipped"
assert "Symlink candidates are never removed automatically" in candidate["detail"]
PY

ORIGINAL="$TMP_DIR/original.txt"
BACKUP="$TMP_DIR/backup.txt"
BACKUP_REPORT="$TMP_DIR/backup-report.json"
RESTORE_REPORT="$TMP_DIR/restore-report.json"
printf "current" > "$ORIGINAL"
printf "backup" > "$BACKUP"
/usr/bin/python3 - "$ORIGINAL" "$BACKUP" "$BACKUP_REPORT" <<'PY'
import json
import sys

original, backup, report_path = sys.argv[1:4]
report = {
    "generatedAt": "2026-01-01T00:00:00Z",
    "command": "backup",
    "toolVersion": "test",
    "app": {
        "appPath": original,
        "bundleIdentifier": "com.example.RestoreTarget",
        "bundleName": "RestoreTarget",
        "displayName": "RestoreTarget",
        "executableName": "RestoreTarget",
        "normalizedNames": ["RestoreTarget"],
        "teamIdentifier": None,
    },
    "summary": {
        "totalCandidates": 1,
        "existingCandidates": 1,
        "trashEligibleExisting": 1,
        "reportOnlyExisting": 0,
        "blockedExisting": 0,
        "totalExistingBytes": 0,
    },
    "candidates": [
        {
            "path": original,
            "reason": "test backup item",
            "confidence": "high",
            "action": "trash",
            "risk": "low",
            "exists": True,
            "isDirectory": False,
            "isSymlink": False,
            "sizeBytes": 0,
            "status": "backedUp",
            "detail": f"Backed up to {backup}",
        }
    ],
}
with open(report_path, "w") as f:
    json.dump(report, f, indent=2, sort_keys=True)
PY
run_cli restore-report "$BACKUP_REPORT" --execute --restore-confirm --json "$RESTORE_REPORT" > "$TMP_DIR/restore.out" 2> "$TMP_DIR/restore.err"
if [[ "$(cat "$ORIGINAL")" != "current" ]]; then
  echo "restore overwrote an existing path" >&2
  exit 1
fi
/usr/bin/python3 - "$RESTORE_REPORT" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    report = json.load(f)

assert report["summary"]["skippedExisting"] == 1
assert report["items"][0]["status"] == "skippedExisting"
PY

echo "CLI safety tests passed"
