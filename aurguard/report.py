import json
import sys
from dataclasses import asdict

COLORS = {"critical": "\033[1;41;97m", "high": "\033[1;31m", "medium": "\033[33m", "info": "\033[36m"}
RESET, BOLD, GREEN, DIM = "\033[0m", "\033[1m", "\033[32m", "\033[2m"


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def print_text(findings, scanned: int, db_version, warnings) -> None:
    for w in warnings:
        print(_c(COLORS["medium"], f"warning: {w}"))
    print(_c(BOLD, f"aurguard: scanned {scanned} foreign packages (threat DB v{db_version})"))
    if not findings:
        print(_c(GREEN, "✓ No threats found."))
        return
    for f in findings:
        print(f"\n{_c(COLORS.get(f.severity, ''), f' {f.severity.upper()} ')} {_c(BOLD, f.package)} {f.version}")
        print(f"   {f.reason}")
        for d in f.details:
            print(_c(DIM, f"   • {d}"))
    crit = [f for f in findings if f.severity == "critical"]
    if crit:
        print(_c(COLORS["critical"], "\n !! Known malware installed. Remove it now: "),
              f"sudo pacman -Rns {' '.join(sorted({f.package for f in crit}))}")
        print("    Then assume this machine is compromised: rotate passwords/SSH keys and check ~/.config/autostart, "
              "systemctl list-units, crontab -l.")


def print_json(findings, scanned: int, db_version, warnings) -> None:
    print(json.dumps({"scanned": scanned, "db_version": db_version, "warnings": warnings,
                      "findings": [asdict(f) for f in findings]}, indent=2))
