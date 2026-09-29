#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if command -v py >/dev/null 2>&1 && py -3.12 --version >/dev/null 2>&1; then
  python_cmd=(py -3.12)
elif command -v py >/dev/null 2>&1; then
  python_cmd=(py -3)
elif command -v python3 >/dev/null 2>&1; then
  python_cmd=(python3)
elif command -v python >/dev/null 2>&1; then
  python_cmd=(python)
else
  echo "Python 3.11 or newer is required." >&2
  exit 1
fi

python_version="$(${python_cmd[@]} -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
if ! "${python_cmd[@]}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required; found $python_version." >&2
  exit 1
fi

echo "Using Python $python_version"
if [[ ! -d .venv ]]; then
  "${python_cmd[@]}" -m venv .venv
fi

if [[ -f .venv/Scripts/activate ]]; then
  # Windows Git Bash
  source .venv/Scripts/activate
elif [[ -f .venv/bin/activate ]]; then
  # Linux/macOS fallback
  source .venv/bin/activate
else
  echo "Virtual environment activation script was not created." >&2
  exit 1
fi

python -m pip install --upgrade pip
python -m pip install -r requirements-runtime.lock
python -m pip install -e . --no-deps
python -W error::ResourceWarning -m unittest discover -s tests -q

echo "AAK setup complete. Run: ./run-tests-gitbash.sh"
