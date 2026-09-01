#!/bin/zsh

set -euo pipefail

readonly PROJECT_DIR="${0:A:h:h}"
readonly PYTHON_EXECUTABLE="$PROJECT_DIR/venv/bin/python"
readonly MACOS_APP="${TMPDIR:-/tmp}/rvi-sentinel-app/RVI-Sentinel.app"

if [[ ! -x "$PYTHON_EXECUTABLE" ]]; then
  print -u2 "RVI-Sentinel GUI environment not found: $PROJECT_DIR/venv"
  print -u2 "Create it with:"
  print -u2 "  python3 -m venv '$PROJECT_DIR/venv'"
  print -u2 "  '$PROJECT_DIR/venv/bin/python' -m pip install -r '$PROJECT_DIR/requirements-gui.txt'"
  exit 1
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  "$PROJECT_DIR/scripts/build_macos_app.sh"
  if [[ "${1:-}" == "--smoke-test" ]]; then
    /usr/bin/open -n -W "$MACOS_APP" --args --project-dir "$PROJECT_DIR" "$@"
    exit 0
  fi
  /usr/bin/open -n "$MACOS_APP" --args --project-dir "$PROJECT_DIR" "$@"
  exit 0
fi

exec "$PYTHON_EXECUTABLE" "$PROJECT_DIR/gui.py" "$@"
