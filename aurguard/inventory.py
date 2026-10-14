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
