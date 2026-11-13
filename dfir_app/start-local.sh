#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DFIR_TOOLKIT_PATH="${DFIR_TOOLKIT_PATH:-$APP_DIR/dfir_toolkit.py}"
export DFIR_LOCAL_OUTPUT="${DFIR_LOCAL_OUTPUT:-$APP_DIR/output}"
export DFIR_LOG_DIR="${DFIR_LOG_DIR:-$APP_DIR/logs}"

mkdir -p "$DFIR_LOCAL_OUTPUT" "$DFIR_LOG_DIR" "$APP_DIR/data"
exec python3 "$APP_DIR/local_connector.py"
