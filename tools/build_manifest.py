#!/usr/bin/env python3
"""Regenerate feed/manifest.json (bumps version, recomputes sha256) and sync the bundled copy.

Run after every edit to feed/threats.json or feed/rules.json:  python tools/build_manifest.py
"""
import datetime
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEED = ROOT / "feed"
BUNDLED = ROOT / "aurguard" / "data"
FILES = ("threats.json", "rules.json")

manifest_path = FEED / "manifest.json"
old = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"version": 0}
sha = {f: hashlib.sha256((FEED / f).read_bytes()).hexdigest() for f in FILES}
for f in FILES:
    json.loads((FEED / f).read_text())  # validate

if sha != old.get("sha256"):
    old["version"] = old.get("version", 0) + 1
    old["updated"] = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
old["sha256"] = sha
old.setdefault("min_client_version", "0.1.0")
manifest_path.write_text(json.dumps(old, indent=2) + "\n")

BUNDLED.mkdir(exist_ok=True)
for f in (*FILES, "manifest.json"):
    shutil.copy(FEED / f, BUNDLED / f)
print(f"feed v{old['version']}")
