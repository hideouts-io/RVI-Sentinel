#!/bin/zsh

set -euo pipefail

readonly PROJECT_DIR="${0:A:h:h}"
readonly PYTHON_EXECUTABLE="$PROJECT_DIR/venv/bin/python"

if [[ ! -x "$PYTHON_EXECUTABLE" ]]; then
  print -u2 "RVI-Sentinel GUI environment not found: $PROJECT_DIR/venv"
  print -u2 "Create it with:"
  print -u2 "  python3 -m venv '$PROJECT_DIR/venv'"
  print -u2 "  '$PROJECT_DIR/venv/bin/python' -m pip install -r '$PROJECT_DIR/requirements-gui.txt'"
  exit 1
fi

exec "$PYTHON_EXECUTABLE" "$PROJECT_DIR/gui.py" "$@"
