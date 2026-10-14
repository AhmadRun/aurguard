# aurguard

A self-updating malware scanner for AUR packages (yay, paru, makepkg) on Arch Linux.

Unlike one-time check scripts, aurguard **keeps itself current**:

| Layer | How it stays up to date |
|---|---|
| Known-malware blocklist | `feed/threats.json`. Every user downloads it automatically every 6h, sha256-verified. |
| Behaviour rules (catch *unknown* malware) | `feed/rules.json`, delivered through the same auto-update. |
| Feed maintenance | A daily GitHub Action (`tools/watch_aur.py`) scans every AUR package changed in the last 24h and opens a PR with suspects. |
| Scheduled scans | systemd user timers: DB update every 6h, full scan daily, desktop notification on danger. |

## Install
```sh
git clone https://github.com/CHANGE-ME/aurguard && cd aurguard
pip install --user .        # or: makepkg -si  (PKGBUILD included)
aurguard update
aurguard scan
aurguard enable             # turn on automatic updates + daily scans
```

## Commands
- `aurguard scan [pkg...] [--json] [--notify] [--offline] [--update]`: exit code 0 = clean, 1 = high, 3 = critical
- `aurguard update`: fetch the latest threat feed
- `aurguard status`: DB version, last scan, timer state
- `aurguard enable` / `disable`: systemd timers

Config (optional): `~/.config/aurguard/config.toml`
```toml
feed_url = "https://raw.githubusercontent.com/you/aurguard/main/feed"
timeout = 15
```

## Adding new malware (maintainers)
1. Add the package to `feed/threats.json` (name, severity, description, date, reference; optional `versions`). Bad AUR accounts go in `maintainers`.
2. Run `python tools/build_manifest.py`. This bumps the version and updates the hashes.
3. Commit and push. Every user gets it within about 6 hours.

## Checks performed
- Known malicious package names, versions and maintainer accounts
- PKGBUILD and `.install` heuristics: pipe-to-shell, base64 exec, reverse shells, paste-site, Discord CDN and raw-IP downloads, shell-rc or autostart persistence, SSH key or browser credential access, and more
- AUR metadata: package deleted from the AUR, orphaned, or brand new with no votes
