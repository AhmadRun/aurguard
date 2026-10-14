"""Installed foreign (AUR / yay / paru) packages."""
import subprocess
from dataclasses import dataclass


@dataclass
class Package:
    name: str
    version: str


def parse(output: str) -> list[Package]:
    pkgs = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append(Package(parts[0], parts[1]))
    return pkgs


def foreign_packages() -> list[Package]:
    out = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True).stdout
    return parse(out)


def all_packages() -> list[Package]:
    out = subprocess.run(["pacman", "-Q"], capture_output=True, text=True).stdout
    return parse(out)


def install_dates(local_db: str = "/var/lib/pacman/local") -> dict[str, int]:
    """{pkgname: install/upgrade unix time} from pacman's local database."""
    import os
    dates = {}
    try:
        entries = os.listdir(local_db)
    except OSError:
        return dates
    for entry in entries:
        try:
            text = open(os.path.join(local_db, entry, "desc")).read()
        except OSError:
            continue
        fields = text.split("\n\n")
        kv = {f.split("\n", 1)[0]: f.split("\n", 1)[1].strip() for f in fields if "\n" in f}
        if "%NAME%" in kv and "%INSTALLDATE%" in kv:
            dates[kv["%NAME%"]] = int(kv["%INSTALLDATE%"])
    return dates
