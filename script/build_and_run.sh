#!/bin/bash
set -euo pipefail
# Automatic host launch and process termination were retired in 2.0.
if [ "$#" -gt 0 ]; then
  echo '旧构建/启动参数已停用。请使用隔离 macOS 构建脚本，完成验收后手动启动交付包。' >&2
  exit 2
fi
exec "$(cd "$(dirname "$0")" && pwd)/build_guest.sh"
