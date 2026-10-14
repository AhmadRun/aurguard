import json
import sys
import tomllib
from dataclasses import asdict
from pathlib import Path

# Nord-ish fallback; replaced by the active Omarchy theme when present.
PALETTE = {"red": "#bf616a", "yellow": "#ebcb8b", "orange": "#d5967a", "green": "#a3be8c",
           "accent": "#81a1c1", "muted": "#4c566a", "foreground": "#d8dee9"}
THEME = Path.home() / ".local/state/omarchy/current/theme/colors.toml"
try:
    PALETTE.update({k: v for k, v in tomllib.loads(THEME.read_text()).items() if isinstance(v, str)})
except Exception:
    pass

RESET = "\033[0m"


def _fg(hexcolor: str, bold: bool = False) -> str:
    h = hexcolor.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"\033[{'1;' if bold else ''}38;2;{r};{g};{b}m"


def _bg(hexcolor: str) -> str:
    h = hexcolor.lstrip("#")
    return f"\033[1;48;2;{int(h[0:2], 16)};{int(h[2:4], 16)};{int(h[4:6], 16)}m\033[38;2;0;0;0m"


SEV = {"critical": "red", "high": "orange", "medium": "yellow", "info": "accent"}


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def print_text(findings, scanned: int, db_version, warnings) -> None:
    P = PALETTE
    for w in warnings:
        print(_c(_fg(P["yellow"]), f"  {w}"))
    print(_c(_fg(P["accent"], True), "  aurguard") + _c(_fg(P["muted"]), f"  ·  {scanned} AUR packages  ·  threat DB v{db_version}"))
    if not findings:
        print(_c(_fg(P["green"], True), "  ✓ No threats found"))
        return
    for f in findings:
        color = P[SEV.get(f.severity, "accent")]
        print(f"\n  {_c(_bg(color), f' {f.severity.upper()} ')}  {_c(_fg(P['foreground'], True), f.package)} "
              f"{_c(_fg(P['muted']), f.version)}")
        print(f"     {_c(_fg(color), f.reason)}")
        for d in f.details:
            print(_c(_fg(P["muted"]), f"     │ {d}"))
    crit = sorted({f.package for f in findings if f.severity == "critical"})
    if crit:
        print("\n" + _c(_fg(P["red"], True), "  Known malware installed. Remove it now:"))
        print(_c(_fg(P["foreground"], True), f"     sudo pacman -Rns {' '.join(crit)}"))
        print(_c(_fg(P["muted"]), "     Then treat this machine as compromised: rotate passwords and SSH keys, and check\n"
                                 "     ~/.config/autostart, systemctl list-units, crontab -l"))


def print_json(findings, scanned: int, db_version, warnings) -> None:
    print(json.dumps({"scanned": scanned, "db_version": db_version, "warnings": warnings,
                      "findings": [asdict(f) for f in findings]}, indent=2))
