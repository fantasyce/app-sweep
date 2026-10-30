#!/bin/sh
set -eu
# Retires the old HOME-only fixture setup and all direct host product execution.
exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/test_isolated.sh" --cli "$@"
