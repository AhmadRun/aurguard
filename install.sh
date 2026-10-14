#!/usr/bin/env bash
# aurguard installer: per-user, no sudo needed.
#   git clone https://github.com/AhmadRun/aurguard && cd aurguard && ./install.sh
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="${XDG_DATA_HOME:-$HOME/.local/share}/aurguard/app"
BIN="$HOME/.local/bin"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

say()  { printf '\033[1;34m::\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v pacman >/dev/null || fail "aurguard is for Arch Linux (pacman not found)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null \
  || fail "Python 3.11+ required: sudo pacman -S python"

say "Installing aurguard to $APP"
rm -rf "$APP"
mkdir -p "$APP" "$BIN"
cp -r "$SRC/aurguard" "$SRC/systemd" "$SRC/LICENSE" "$SRC/README.md" "$SRC/uninstall.sh" "$APP/"
[ -d "$SRC/omarchy-plugin" ] && cp -r "$SRC/omarchy-plugin" "$APP/"

cat > "$BIN/aurguard" <<LAUNCHER
#!/bin/sh
PYTHONPATH="$APP" exec python3 -m aurguard "\$@"
LAUNCHER
chmod +x "$BIN/aurguard"

if command -v systemctl >/dev/null; then
  say "Enabling automatic protection (DB update every 6h, daily scan)"
  mkdir -p "$UNITS"
  for unit in "$APP"/systemd/aurguard-*; do
    sed "s#/usr/bin/aurguard#$BIN/aurguard#" "$unit" > "$UNITS/$(basename "$unit")"
  done
  systemctl --user daemon-reload
  systemctl --user enable --now aurguard-update.timer aurguard-scan.timer >/dev/null
fi

if command -v omarchy >/dev/null && [ -d "$APP/omarchy-plugin" ]; then
  say "Omarchy detected: adding the AUR Guard bar widget"
  "$APP/omarchy-plugin/install.sh" >/dev/null || true
fi

case ":$PATH:" in *":$BIN:"*) ;; *) say "Add $BIN to your PATH to run 'aurguard' directly" ;; esac

say "Downloading the latest threat lists"
"$BIN/aurguard" update || true
say "Running first scan"
"$BIN/aurguard" scan || true

echo
say "Done. Commands: aurguard scan | aurguard status | aurguard update"
say "Uninstall with: $SRC/uninstall.sh (or ~/.local/share/aurguard/app/uninstall.sh)"
