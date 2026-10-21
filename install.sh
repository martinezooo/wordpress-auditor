#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd -P)"
VENV_DIR="$HOME/.local/share/wordpress-auditor/venv"
BIN_DIR="$HOME/.local/bin"
FLATTEN=0
if [ "$#" -gt 0 ]; then
  case "$1" in
    --fix-layout) FLATTEN=1 ;;
    -h|--help)
      echo "Usage: bash install.sh [--fix-layout]"
      echo "Installs WordPress Auditor to ~/.local/bin; --fix-layout safely flattens a nested checkout."
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; assert sys.version_info >= (3, 10)' >/dev/null 2>&1; then
  echo "Python 3.10+ required. Kali: sudo apt install python3 python3-venv" >&2
  exit 1
fi
mkdir -p "$BIN_DIR" "$(dirname "$VENV_DIR")"
if [ -e "$BIN_DIR/wordpress-auditor" ] || [ -L "$BIN_DIR/wordpress-auditor" ]; then
  expected="$VENV_DIR/bin/wordpress-auditor"
  actual="$(readlink "$BIN_DIR/wordpress-auditor" 2>/dev/null || true)"
  if [ "$actual" != "$expected" ]; then
    echo "Refusing to overwrite an existing command: $BIN_DIR/wordpress-auditor" >&2
    exit 1
  fi
fi
if [ -e "$BIN_DIR/wordpress-auditor-update" ] || [ -L "$BIN_DIR/wordpress-auditor-update" ]; then
  if ! grep -Fq '# WordPress Auditor managed updater' "$BIN_DIR/wordpress-auditor-update" 2>/dev/null; then
    if ! grep -Fq 'git+https://github.com/martinezooo/wordpress-auditor.git@main'            "$BIN_DIR/wordpress-auditor-update" 2>/dev/null; then
      echo "Refusing to overwrite an existing updater: $BIN_DIR/wordpress-auditor-update" >&2
      exit 1
    fi
  fi
fi
if ! python3 -m venv "$VENV_DIR"; then
  echo "Unable to create isolated virtualenv. Kali: sudo apt install python3-venv" >&2
  exit 1
fi
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --upgrade "$ROOT"
ln -sfn "$VENV_DIR/bin/wordpress-auditor" "$BIN_DIR/wordpress-auditor"
cat > "$BIN_DIR/wordpress-auditor-update" <<'UPD'
#!/usr/bin/env bash
# WordPress Auditor managed updater
set -euo pipefail
VENV_DIR="$HOME/.local/share/wordpress-auditor/venv"
if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "WordPress Auditor is not installed in $VENV_DIR." >&2
  exit 1
fi
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --upgrade \
  --force-reinstall 'git+https://github.com/martinezooo/wordpress-auditor.git@main'
"$VENV_DIR/bin/wordpress-auditor" --version
UPD
chmod 755 "$BIN_DIR/wordpress-auditor-update"
"$VENV_DIR/bin/wordpress-auditor" --version
if [ "$FLATTEN" -eq 1 ]; then
  bash "$ROOT/scripts/flatten-checkout.sh"
fi
echo "Installed: $VENV_DIR"
echo "Update: $BIN_DIR/wordpress-auditor-update"
if ! command -v wordpress-auditor >/dev/null 2>&1; then
  echo "In this terminal, run: $BIN_DIR/wordpress-auditor --help"
  echo "If needed, add ~/.local/bin to PATH in your shell startup file."
else
  echo "Ready: wordpress-auditor --help"
fi
