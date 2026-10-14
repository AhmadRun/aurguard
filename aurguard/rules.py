"""Heuristic rule engine: regex rules (from the feed) applied to PKGBUILD / .install files."""
import re
from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Hit:
    rule_id: str
    severity: str
    description: str
    file: str
    line_no: int
    line: str


def compile_rules(ruleset: dict) -> list[tuple[dict, re.Pattern, re.Pattern | None]]:
    compiled = []
    for r in ruleset.get("rules", []):
        try:
            exclude = re.compile(r["exclude"], re.IGNORECASE) if r.get("exclude") else None
            compiled.append((r, re.compile(r["pattern"], re.IGNORECASE), exclude))
        except re.error:
            continue  # a broken rule must never crash a scan
    return compiled


def apply(compiled, files: dict[str, str]) -> list[Hit]:
    hits = []
    for fname, content in files.items():
        lines = content.splitlines()
        for rule, rx, exclude in compiled:
            for i, line in enumerate(lines, 1):
                if line.lstrip().startswith("#") or (exclude and exclude.search(line)):
                    continue
                if rx.search(line):
                    hits.append(Hit(rule["id"], rule["severity"], rule["description"], fname, i, line.strip()[:200]))
                    break  # one hit per rule per file is enough
    return hits
