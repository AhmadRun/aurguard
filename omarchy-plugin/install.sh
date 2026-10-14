#!/bin/sh
# Install the AUR Guard bar widget into Omarchy and put it on the bar.
set -e
src="$(cd "$(dirname "$0")" && pwd)"
dest="$HOME/.config/omarchy/plugins/io.github.ahmadrun.aurguard"
rm -rf "$dest"
cp -r "$src" "$dest"
rm -f "$dest/install.sh"
omarchy bar put io.github.ahmadrun.aurguard --after io.github.ahmadrun.prayer-times 2>/dev/null \
  || omarchy bar put io.github.ahmadrun.aurguard
echo "AUR Guard installed. If it does not appear, run: omarchy restart shell"
