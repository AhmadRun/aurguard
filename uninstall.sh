#!/usr/bin/env bash
# Remove aurguard (keeps nothing behind except your config, if any).
set -u
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
systemctl --user disable --now aurguard-update.timer aurguard-scan.timer 2>/dev/null
rm -f "$UNITS"/aurguard-*
systemctl --user daemon-reload 2>/dev/null
rm -f "$HOME/.local/bin/aurguard"
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/aurguard" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/aurguard" \
       "${XDG_CACHE_HOME:-$HOME/.cache}/aurguard"
if [ -d "$HOME/.config/omarchy/plugins/io.github.ahmadrun.aurguard" ]; then
  qs ipc -p /usr/share/omarchy/shell call shell setPluginEnabled io.github.ahmadrun.aurguard false >/dev/null 2>&1
  rm -rf "$HOME/.config/omarchy/plugins/io.github.ahmadrun.aurguard"
fi
echo "aurguard removed."
