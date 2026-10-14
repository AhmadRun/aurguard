"""Combine blocklist, heuristics and AUR metadata into findings."""
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field

from . import aur, rules
from .inventory import Package
from .paths import CACHE_DIR


@dataclass
class Finding:
    package: str
    version: str
    severity: str
    reason: str
    details: list[str] = field(default_factory=list)


def _cache_path():
    return CACHE_DIR / "pkgbuild-scan.json"


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text())
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    _cache_path().parent.mkdir(parents=True, exist_ok=True)
    _cache_path().write_text(json.dumps(cache))


def check_blocklist(pkgs: list[Package], threats: dict) -> list[Finding]:
    by_name = {t["name"]: t for t in threats.get("packages", [])}
    out = []
    for p in pkgs:
        t = by_name.get(p.name)
        if not t:
            continue
        versions = t.get("versions")
        if versions and p.version not in versions:
            continue
        out.append(Finding(p.name, p.version, t.get("severity", "critical"),
                           f"KNOWN MALWARE: {t.get('description', '')}",
                           [s for s in [t.get("reference"), f"reported {t.get('date', '?')}"] if s]))
    return out


def _day(s: str) -> float:
    import datetime
    return datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.UTC).timestamp()


def check_campaigns(pkgs: list[Package], upstream: dict, installed_at: dict[str, int],
                    skip: set[str]) -> list[Finding]:
    """Community campaign lists. A name match is only *critical* if the package was installed or
    upgraded on/after the campaign started (packages were hijacked temporarily, then cleaned)."""
    out = []
    for c in upstream.get("campaigns", []):
        names = set(c.get("packages", []))
        win = c.get("window")
        for p in pkgs:
            if p.name in skip or p.name not in names:
                continue
            when = installed_at.get(p.name)
            ref = f"campaign: {c['display']}"
            if not win or when is None:
                out.append(Finding(p.name, p.version, "critical", f"KNOWN MALWARE ({c['display']})", [ref]))
            elif when >= _day(win["start"]):
                out.append(Finding(p.name, p.version, "critical",
                                   f"Installed/updated after {c['display']} began — likely infected",
                                   [ref, f"installed {time.strftime('%Y-%m-%d', time.localtime(when))}, "
                                         f"attack window {win['start']} → {win['end']}"]))
            else:
                out.append(Finding(p.name, p.version, "medium",
                                   f"Package was hijacked in {c['display']}, but your copy predates it",
                                   [ref, f"installed {time.strftime('%Y-%m-%d', time.localtime(when))}. "
                                         "Do NOT update it until you verify the current PKGBUILD."]))
            skip = skip | {p.name}
    return out


def check_iocs(upstream: dict) -> list[Finding]:
    """Look for known malware files on disk (e.g. the fake ~/.local/bin/sudo password grabber)."""
    import os
    out = []
    for c in upstream.get("campaigns", []):
        for ioc in c.get("iocs", []):
            path = os.path.expanduser(ioc.get("path", ""))
            if not path or not os.path.isfile(path):
                continue
            try:
                digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
            except OSError:
                continue
            if digest == ioc.get("sha256"):
                out.append(Finding(path, "-", "critical", f"MALWARE FILE FOUND: {ioc.get('description', '')}",
                                   [f"campaign: {c['display']}", "Delete it and treat the system as compromised."]))
    return out


def check_metadata(pkgs: list[Package], meta: dict[str, dict], blocked: set[str],
                   bad_maintainers: set[str] = frozenset()) -> list[Finding]:
    out = []
    now = time.time()
    for p in pkgs:
        if p.name in blocked:
            continue
        m = meta.get(p.name)
        if m and m.get("Maintainer") in bad_maintainers:
            out.append(Finding(p.name, p.version, "critical",
                               f"Maintained by known malicious account '{m['Maintainer']}'"))
            continue
        if m is None:
            out.append(Finding(p.name, p.version, "medium", "Package no longer exists on the AUR",
                               ["Removed packages are sometimes deleted for being malicious. Verify why it was removed."]))
            continue
        if m.get("Maintainer") is None:
            out.append(Finding(p.name, p.version, "info", "Package is orphaned",
                               ["Anyone can adopt it and push a malicious update."]))
        age_days = (now - m.get("FirstSubmitted", now)) / 86400
        if age_days < 30 and m.get("NumVotes", 0) < 3:
            out.append(Finding(p.name, p.version, "medium", "Very new package with almost no votes",
                               [f"submitted {age_days:.0f} days ago, {m.get('NumVotes', 0)} votes"]))
    return out


def check_pkgbuilds(pkgs: list[Package], meta: dict[str, dict], ruleset: dict, timeout: int) -> list[Finding]:
    compiled = rules.compile_rules(ruleset)
    rules_key = hashlib.sha256(json.dumps(ruleset, sort_keys=True).encode()).hexdigest()[:16]
    cache = _load_cache()
    out = []
    for p in pkgs:
        m = meta.get(p.name)
        if not m:
            continue
        base = m.get("PackageBase", p.name)
        key = f"{base}:{m.get('Version')}:{rules_key}"
        if key in cache:
            hits = [rules.Hit(**h) for h in cache[key]]
        else:
            files = aur.fetch_sources(base, timeout)
            hits = rules.apply(compiled, files) if files else []
            if files:
                cache[key] = [asdict(h) for h in hits]
        if hits:
            worst = max(hits, key=lambda h: rules.SEVERITY_ORDER[h.severity])
            out.append(Finding(p.name, p.version, worst.severity,
                               f"Suspicious PKGBUILD ({len(hits)} rule{'s' if len(hits) > 1 else ''})",
                               [f"[{h.rule_id}] {h.description} — {h.file}:{h.line_no}: {h.line}" for h in hits]))
    _save_cache(cache)
    return out


def scan(pkgs: list[Package], threats: dict, ruleset: dict, online: bool = True, timeout: int = 15,
         log=lambda msg: None, upstream: dict | None = None,
         installed_at: dict[str, int] | None = None) -> tuple[list[Finding], list[str]]:
    """Returns (findings, warnings)."""
    warnings = []
    upstream = upstream or {}
    findings = check_blocklist(pkgs, threats)
    findings += check_campaigns(pkgs, upstream, installed_at or {}, {f.package for f in findings})
    findings += check_iocs(upstream)
    blocked = {f.package for f in findings}
    bad_accounts = set(threats.get("maintainers", []))
    for c in upstream.get("campaigns", []):
        bad_accounts.update(c.get("accounts", []))
    if online and pkgs:
        try:
            log("Querying AUR metadata...")
            meta = aur.info([p.name for p in pkgs], timeout)
            findings += check_metadata(pkgs, meta, blocked, bad_accounts)
            log("Analysing PKGBUILDs...")
            findings += check_pkgbuilds([p for p in pkgs if p.name not in blocked], meta, ruleset, timeout)
        except Exception as e:
            warnings.append(f"AUR unreachable, ran blocklist check only: {e}")
    findings.sort(key=lambda f: -rules.SEVERITY_ORDER.get(f.severity, 0))
    return findings, warnings
