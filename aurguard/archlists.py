"""Official Arch mailing lists as a live malware source.

aur-requests: every AUR deletion request is posted here (by users and Package Maintainers).
aur-general:  where people report malicious packages.

Each list's RSS feed holds only the newest ~30 posts (~1 day), so every report we see is
accumulated in DATA_DIR/arch-lists.json and kept. Updating every 6 h keeps up with the feed.
"""
import email.utils
import json
import os
import re
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .paths import DATA_DIR

LISTS = ("aur-requests", "aur-general")
FEED = "https://lists.archlinux.org/archives/list/{name}@lists.archlinux.org/feed/"

KEYWORDS = re.compile(r"\b(malware|malicious|trojan|backdoor|infostealer|stealer|rootkit|keylogger|"
                      r"crypto ?miner|cryptominer|\brat\b|remote access trojan|compromised|hijack(ed)?|"
                      r"exfiltrat\w*|reverse shell|virus)", re.IGNORECASE)
SUBJECT_PKG = re.compile(r"\[PRQ#\d+\]\s+Deletion Request for\s+(\S+)", re.IGNORECASE)
URL_PKG = re.compile(r"aur\.archlinux\.org/(?:packages|pkgbase|cgit/aur\.git/\w+/\S*\?h=)/?([A-Za-z0-9@._+-]+)")
STATE_FILE = "arch-lists.json"


def _get(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"aurguard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse_feed(xml_text: str, list_name: str) -> list[dict]:
    """Return malware reports: [{package, list, title, link, date}]."""
    root = ET.fromstring(xml_text)
    reports = []
    for item in root.iter("item"):
        title = item.findtext("title") or ""
        body = item.findtext("description") or ""
        if not KEYWORDS.search(title + "\n" + body):
            continue
        pkgs = set()
        m = SUBJECT_PKG.search(title)
        if m:
            pkgs.add(m.group(1))
        elif list_name == "aur-general":
            pkgs.update(p.rstrip("/.") for p in URL_PKG.findall(body))
        try:
            date = email.utils.parsedate_to_datetime(item.findtext("pubDate")).strftime("%Y-%m-%d")
        except Exception:
            date = "?"
        for p in pkgs:
            reports.append({"package": p, "list": list_name, "title": title.strip(),
                            "link": (item.findtext("link") or "").strip(), "date": date})
    return reports


def load(data_dir: Path = DATA_DIR) -> dict:
    try:
        return json.loads((data_dir / STATE_FILE).read_text())
    except Exception:
        return {"reports": [], "checked": None}


def update(timeout: int = 40, data_dir: Path = DATA_DIR, get=_get,
           cloud_url: str | None = None) -> tuple[int, list[str]]:
    """Fetch feeds, merge new reports. Returns (new_report_count, errors).

    cloud_url: the aurguard feed's arch-lists.json, collected every 6 h by a GitHub Action,
    so reports posted while this machine was off are not missed."""
    import datetime
    state = load(data_dir)
    seen = {(r["package"], r["link"]) for r in state["reports"]}
    new, errors = 0, []
    if cloud_url:
        try:
            for r in json.loads(get(cloud_url, timeout)).get("reports", []):
                if (r["package"], r["link"]) not in seen:
                    state["reports"].append(r)
                    seen.add((r["package"], r["link"]))
                    new += 1
        except Exception as e:
            errors.append(f"cloud history: {e}")
    for name in LISTS:
        try:
            for r in parse_feed(get(FEED.format(name=name), timeout), name):
                if (r["package"], r["link"]) not in seen:
                    state["reports"].append(r)
                    seen.add((r["package"], r["link"]))
                    new += 1
        except Exception as e:
            errors.append(f"{name}: {e}")
    if sum(not e.startswith("cloud") for e in errors) < len(LISTS):
        state["checked"] = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    data_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=data_dir)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, data_dir / STATE_FILE)
    return new, errors
