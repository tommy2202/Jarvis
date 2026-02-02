#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

py=""
if [[ -x ".venv/bin/python" ]]; then
  py=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  py="python3"
elif command -v python >/dev/null 2>&1; then
  py="python"
else
  echo "Python not found. Install Python or create a venv." >&2
  exit 1
fi

echo "Running bytecode compilation..."
$py -m compileall jarvis

echo "Running unit tests..."
$py -m pytest -q

echo "Dev check completed."
