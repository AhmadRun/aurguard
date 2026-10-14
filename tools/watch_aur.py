#!/usr/bin/env python3
"""Daily AUR watcher — keeps the feed from going stale.

Downloads the AUR's full metadata dump, takes every package changed in the last N hours,
runs the heuristic rules on its PKGBUILD, and writes suspicious ones to feed/candidates.json.
A human reviews candidates and moves real malware into feed/threats.json
(then runs tools/build_manifest.py), which ships to every user on their next update.

Usage: python tools/watch_aur.py [--hours 24] [--min-severity high]
"""
import argparse
import gzip
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aurguard import aur, rules  # noqa: E402

META_URL = "https://aur.archlinux.org/packages-meta-v1.json.gz"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--min-severity", default="high", choices=list(rules.SEVERITY_ORDER))
    ap.add_argument("--limit", type=int, default=3000, help="max PKGBUILDs to fetch")
    args = ap.parse_args()

    req = urllib.request.Request(META_URL, headers={"User-Agent": "aurguard-watcher"})
    with urllib.request.urlopen(req, timeout=120) as r:
        meta = json.loads(gzip.decompress(r.read()))
    cutoff = time.time() - args.hours * 3600
    threats = json.loads((ROOT / "feed/threats.json").read_text())
    known = {t["name"] for t in threats["packages"]}
    bad_maint = set(threats.get("maintainers", []))
    compiled = rules.compile_rules(json.loads((ROOT / "feed/rules.json").read_text()))
    floor = rules.SEVERITY_ORDER[args.min_severity]

    recent = {}
    for p in meta:
        if p["LastModified"] >= cutoff and p["Name"] not in known:
            recent.setdefault(p["PackageBase"], p)
    print(f"{len(recent)} package bases changed in last {args.hours}h", file=sys.stderr)

    cands_path = ROOT / "feed/candidates.json"
    cands = json.loads(cands_path.read_text()) if cands_path.exists() else {"candidates": []}
    seen = {(c["name"], c["version"]) for c in cands["candidates"]}
    new = 0
    for base, p in list(recent.items())[: args.limit]:
        if (p["Name"], p["Version"]) in seen:
            continue
        reasons = []
        if p.get("Maintainer") in bad_maint:
            reasons.append(f"known malicious maintainer {p['Maintainer']}")
        hits = [h for h in rules.apply(compiled, aur.fetch_sources(base)) if rules.SEVERITY_ORDER[h.severity] >= floor]
        reasons += [f"[{h.rule_id}] {h.file}:{h.line_no}: {h.line}" for h in hits]
        if reasons:
            cands["candidates"].append({
                "name": p["Name"], "version": p["Version"], "maintainer": p.get("Maintainer"),
                "url": f"https://aur.archlinux.org/packages/{p['Name']}",
                "found": time.strftime("%Y-%m-%d"), "reasons": reasons})
            new += 1
            print(f"CANDIDATE {p['Name']} {p['Version']}: {reasons[0]}", file=sys.stderr)
        time.sleep(0.2)  # be polite to aur.archlinux.org
    cands_path.write_text(json.dumps(cands, indent=2) + "\n")
    print(f"{new} new candidates", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
