#!/usr/bin/env python3
"""Collect malware reports from the Arch mailing lists into feed/arch-lists.json.

Run every 6 h by .github/workflows/arch-lists.yml, so reports are gathered 24/7
even when users' machines are off. Clients merge this file on `aurguard update`.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aurguard import archlists  # noqa: E402

new, errors = archlists.update(data_dir=ROOT / "feed")
for e in errors:
    print(f"error: {e}", file=sys.stderr)
print(f"{new} new reports, {len(archlists.load(ROOT / 'feed')['reports'])} total")
sys.exit(1 if len(errors) == len(archlists.LISTS) else 0)
