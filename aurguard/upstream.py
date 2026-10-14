"""Community malware lists (lenucksi/aur-malware-check + official Arch HedgeDoc).

These are fetched directly on every `aurguard update`, so the scanner stays current
even without our own feed. Result is normalised into DATA_DIR/upstream.json:

  {"fetched": "...", "campaigns": [{"id", "display", "window": {"start","end"}|null,
    "packages": [...], "accounts": [...], "iocs": [{"path","sha256","description"}]}]}
"""
import datetime
import json
import os
import tempfile
import urllib.request
from pathlib import Path

from . import __version__
from .paths import BUNDLED, DATA_DIR

BASE = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/"


def _get(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"aurguard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse_list(text: str) -> list[str]:
    """One package per line; ignores comments, blank lines and markdown fences."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("```") and " " not in line:
            out.append(line)
    return out


def fetch(timeout: int = 20, get=_get, base: str = BASE) -> dict:
    index = json.loads(get(base + "data/campaigns.json", timeout))
    campaigns = []
    for c in index.get("campaigns", []):
        if c.get("type") != "aur":
            continue
        pkgs: set[str] = set()
        for path in c.get("lists", []):
            try:
                pkgs.update(parse_list(get(base + path, timeout)))
            except Exception:
                pass  # e.g. optional extra list missing
        if c.get("refresh_url"):
            try:
                pkgs.update(parse_list(get(c["refresh_url"], timeout)))
            except Exception:
                pass
        accounts = []
        acc_path = next((s for s in c.get("sources", {}) if s.endswith("accounts.json")), None)
        if acc_path:
            try:
                accounts = sorted(json.loads(get(base + acc_path, timeout)).get("accounts", {}))
            except Exception:
                pass
        campaigns.append({"id": c["id"], "display": c.get("display", c["id"]),
                          "window": c.get("date_window"), "packages": sorted(pkgs),
                          "accounts": accounts, "iocs": c.get("ioc_files", [])})
    if not any(c["packages"] for c in campaigns):
        raise ValueError("upstream returned no packages")
    return {"fetched": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": base, "campaigns": campaigns}


def save(data: dict, data_dir: Path = DATA_DIR) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=data_dir)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, data_dir / "upstream.json")


def load(data_dir: Path = DATA_DIR) -> dict:
    for p in (data_dir / "upstream.json", BUNDLED / "upstream.json"):
        if p.exists():
            return json.loads(p.read_text())
    return {"campaigns": []}
