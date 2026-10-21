#!/usr/bin/env bash
# Flatten ONLY wordpress-auditor/wordpress-auditor. Never delete user files.
set -euo pipefail
REPO="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
OUTER="$(dirname "$REPO")"
PARENT="$(dirname "$OUTER")"
if [ "$(basename "$REPO")" != "wordpress-auditor" ] || \
   [ "$(basename "$OUTER")" != "wordpress-auditor" ]; then
  echo "No duplicate wordpress-auditor/wordpress-auditor checkout to flatten."
  exit 0
fi
if [ ! -d "$REPO/.git" ] || [ ! -f "$REPO/pyproject.toml" ]; then
  echo "Not an expected Git checkout; no changes." >&2
  exit 1
fi
for entry in "$OUTER"/* "$OUTER"/.[!.]* "$OUTER"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  if [ "$entry" != "$REPO" ]; then
    echo "Outer folder has other files; not moving any files: $entry" >&2
    exit 1
  fi
done
STAGED="$PARENT/.wordpress-auditor-move-$$"
if [ -e "$STAGED" ]; then
  echo "Staging path occupied; aborting." >&2
  exit 1
fi
mv -- "$REPO" "$STAGED"
if ! rmdir -- "$OUTER"; then
  mv -- "$STAGED" "$REPO"
  echo "Could not remove outer directory; original layout restored." >&2
  exit 1
fi
if ! mv -- "$STAGED" "$OUTER"; then
  mkdir -p -- "$OUTER"
  mv -- "$STAGED" "$REPO"
  echo "Move failed; original layout restored." >&2
  exit 1
fi
echo "Flattened to $OUTER; Git, .venv, audit and user changes preserved."
