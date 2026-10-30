#!/bin/sh
set -eu
# Host-side orchestration only: compilation and product execution stay in Docker.
ROOT=${APP_SWEEP_TASK_ROOT:?Set an existing dedicated task output directory}
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$ROOT" in /|"$HOME"|"$SOURCE"|/Users|/Volumes|/tmp|/private|/var) echo 'Refusing a broad output root' >&2; exit 2;; esac
[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || exit 2
TOOLCHAIN=${APP_SWEEP_TOOLCHAIN:-"$ROOT/toolchain"}
[ -x "$TOOLCHAIN/usr/bin/swift" ] || { echo 'Provide a verified Linux Swift toolchain' >&2; exit 2; }
OUTPUT="$ROOT/build"
MARKER="$OUTPUT/.app-sweep-isolated-output-v2"
if [ ! -d "$OUTPUT" ]; then mkdir "$OUTPUT"; printf '%s\n' 'App Sweep isolated output v2' > "$MARKER"; fi
[ ! -L "$OUTPUT" ] && [ -f "$MARKER" ] && [ ! -L "$MARKER" ] || { echo 'Output directory ownership has not been established' >&2; exit 2; }
[ "$(cat "$MARKER")" = 'App Sweep isolated output v2' ] || exit 2
NAME="app-sweep-v2-test-$(date +%s)-$$"
if [ "${1:-}" = --cli ]; then
  shift
  set -- /bin/sh -c 'swift build --product app-sweep --scratch-path /out/linux && node /src/Tests/CLI/compatibility.mjs "$(swift build --show-bin-path --scratch-path /out/linux)/app-sweep"'
else
  set -- swift test --scratch-path /out/linux "$@"
fi
docker run --name "$NAME" --label "org.appsweep.task=$(basename "$ROOT")" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus 2 --memory 4g --pids-limit 256 --tmpfs /tmp:rw,exec,size=1g \
  --tmpfs /root/Applications:rw,size=8m --tmpfs /fixture-home:rw,exec,size=128m \
  -e HOME=/tmp/test-home -e APP_SWEEP_FIXTURES=/fixture-home/task \
  -e PATH=/opt/swift/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --mount "type=bind,src=$TOOLCHAIN,dst=/opt/swift,readonly" \
  --mount "type=bind,src=$SOURCE,dst=/src,readonly" \
  --mount "type=bind,src=$OUTPUT,dst=/out" -w /src node:24-bookworm "$@"
