# aurguard

A self-updating malware scanner for AUR packages (yay, paru, makepkg) on Arch Linux.

Unlike one-time check scripts, aurguard **keeps itself current**:

| Layer | How it stays up to date |
|---|---|
| Official Arch mailing lists (live) | Every update reads the RSS feeds of `aur-requests` (all AUR deletion requests) and `aur-general` (malware reports). Any post mentioning malware or a trojan, stealer, backdoor and so on is kept in `~/.local/share/aurguard/arch-lists.json`, and an installed package named in it is flagged **high**. |
| Community lists (no setup needed) | Every `aurguard update` pulls the live lists from [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) and the official Arch HedgeDoc: about 2,000 packages from the June 2026 attack, CHAOS RAT and Russian spam, plus attacker accounts and malware-file hashes. |
| Known-malware blocklist | `feed/threats.json`. Every user downloads it automatically every 6h, sha256-verified. |
| Behaviour rules (catch *unknown* malware) | `feed/rules.json`, delivered through the same auto-update. |
| Feed maintenance | A daily GitHub Action (`tools/watch_aur.py`) scans every AUR package changed in the last 24h and opens a PR with suspects. |
| Scheduled scans | systemd user timers: DB update every 6h, full scan daily, desktop notification on danger. |

## Install
On Arch Linux, Omarchy included. No sudo needed:

```sh
git clone https://github.com/AhmadRun/aurguard
cd aurguard && ./install.sh
```

That's all. The installer:
- installs the `aurguard` command into `~/.local/bin`
- turns on automatic protection: threat lists update every 6 hours and a full scan runs daily, with a desktop notification if something is found
- on **Omarchy**, adds the **AUR Guard** shield to your bar
- downloads the latest threat lists and runs a first scan

To update later: `cd aurguard && git pull && ./install.sh`
To uninstall: `~/.local/share/aurguard/app/uninstall.sh`

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
- Community campaign lists, checked against the **install date**. A package installed or updated after the attack started is *critical*. One installed before the attack is *medium*: don't update it until you've checked it.
- Known malware files on disk, such as the fake `~/.local/bin/sudo` password grabber
- Known malicious package names, versions and maintainer accounts
- PKGBUILD and `.install` heuristics: pipe-to-shell, base64 exec, reverse shells, paste-site, Discord CDN and raw-IP downloads, shell-rc or autostart persistence, SSH key or browser credential access, and more
- AUR metadata: package deleted from the AUR, orphaned, or brand new with no votes

## Omarchy bar widget
`omarchy-plugin/` holds an Omarchy shell widget that matches your theme. It shows a shield that turns red with a count when a dangerous package is found. Click it for a popup with status, findings, **Scan now**, **Update DB** and an **Automatic protection** toggle. Middle-click starts a scan.

```sh
omarchy-plugin/install.sh
```

The CLI output also uses your current Omarchy theme colours.
