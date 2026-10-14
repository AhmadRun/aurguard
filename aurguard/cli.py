"""aurguard command line."""
import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__, archlists, db, inventory, notify, report, scanner, upstream
from .paths import STATE_DIR, load_config

HISTORY = STATE_DIR / "history.jsonl"


def cmd_update(args, cfg) -> int:
    ok = False
    try:
        data = upstream.fetch(cfg["timeout"])
        upstream.save(data)
        total = sum(len(c["packages"]) for c in data["campaigns"])
        print(f"community lists: {total} known-bad packages from {len(data['campaigns'])} campaigns")
        ok = True
    except Exception as e:
        print(f"community lists: update failed ({e}); keeping previous copy", file=sys.stderr)

    new, errs = archlists.update()
    for e in errs:
        print(f"arch mailing lists: {e}", file=sys.stderr)
    if len(errs) < len(archlists.LISTS):
        total = len(archlists.load()["reports"])
        print(f"arch mailing lists: {new} new malware report{'s' if new != 1 else ''} ({total} kept)")
        ok = True

    if "CHANGE-ME" in cfg["feed_url"]:
        print("aurguard feed: not published yet (rules + extra threats use the built-in copy)")
        return 0 if ok else 2
    try:
        changed, manifest = db.update(cfg["feed_url"], cfg["timeout"])
        print(f"aurguard feed: {'updated to' if changed else 'already at'} v{manifest.get('version')}")
        if db.version_tuple(manifest.get("min_client_version", "0")) > db.version_tuple(__version__):
            print(f"warning: aurguard {__version__} is older than required "
                  f"{manifest['min_client_version']}. Please upgrade.", file=sys.stderr)
        ok = True
    except db.UpdateError as e:
        print(f"aurguard feed: update failed ({e})", file=sys.stderr)
    return 0 if ok else 2


def cmd_scan(args, cfg) -> int:
    if args.update:
        cmd_update(args, cfg)
    pkgs = inventory.all_packages() if args.all else inventory.foreign_packages()
    if args.package:
        pkgs = [p for p in pkgs if p.name in args.package] or [inventory.Package(n, "?") for n in args.package]
    threats, ruleset = db.load_threats(), db.load_rules()
    log = (lambda m: print(m, file=sys.stderr)) if not args.json and not args.quiet else (lambda m: None)
    findings, warnings = scanner.scan(pkgs, threats, ruleset, online=not args.offline,
                                      timeout=cfg["timeout"], log=log, upstream=upstream.load(),
                                      installed_at=inventory.install_dates(), archlists=archlists.load())
    dbv = db.local_manifest().get("version")
    (report.print_json if args.json else report.print_text)(findings, len(pkgs), dbv, warnings)

    if not args.package:  # only full-system scans describe this machine's state
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(HISTORY, "a") as f:
            f.write(json.dumps({"time": time.time(), "scanned": len(pkgs), "db_version": dbv,
                                "findings": [asdict(x) for x in findings]}) + "\n")

    serious = [f for f in findings if f.severity in ("critical", "high")]
    if args.notify and serious:
        names = ", ".join(sorted({f.package for f in serious}))
        notify.send("⚠ aurguard: dangerous AUR package detected",
                    f"{names}\nRun `aurguard scan` in a terminal for details.",
                    critical=any(f.severity == "critical" for f in serious))
    if any(f.severity == "critical" for f in findings):
        return 3
    return 1 if serious else 0


def _timers() -> dict:
    if not shutil.which("systemctl"):
        return {}
    out = subprocess.run(["systemctl", "--user", "is-active", "aurguard-scan.timer", "aurguard-update.timer"],
                         capture_output=True, text=True).stdout.split()
    return {"scan": out[0] if out else "unknown", "update": out[1] if len(out) > 1 else "unknown"}


def _last_scan() -> dict | None:
    if not HISTORY.exists():
        return None
    lines = HISTORY.read_text().strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def _community() -> dict:
    u = upstream.load()
    return {"packages": sum(len(c["packages"]) for c in u.get("campaigns", [])),
            "campaigns": len(u.get("campaigns", [])), "fetched": u.get("fetched")}


def cmd_status(args, cfg) -> int:
    m = db.local_manifest()
    if args.json:
        print(json.dumps({"version": __version__, "feed": cfg["feed_url"], "db_version": m.get("version"),
                          "db_updated": m.get("updated"), "known": len(db.load_threats().get("packages", [])),
                          "rules": len(db.load_rules().get("rules", [])), "last_scan": _last_scan(),
                          "community": _community(),
                          "arch_lists": {"reports": len(archlists.load()["reports"]),
                                         "checked": archlists.load()["checked"]},
                          "timers": _timers()}))
        return 0
    print(f"aurguard {__version__}\nfeed: {cfg['feed_url']}\nthreat DB: v{m.get('version')} "
          f"updated {m.get('updated', '?')}, {len(db.load_threats().get('packages', []))} known-bad packages, "
          f"{len(db.load_rules().get('rules', []))} rules")
    c = _community()
    print(f"community lists: {c['packages']} known-bad packages, {c['campaigns']} campaigns, fetched {c['fetched']}")
    a = archlists.load()
    print(f"arch mailing lists: {len(a['reports'])} malware reports kept, last checked {a['checked']}")
    last = _last_scan()
    if last:
        n = len(last["findings"])
        print(f"last scan: {time.strftime('%Y-%m-%d %H:%M', time.localtime(last['time']))}, "
              f"{last['scanned']} packages, {n} finding{'s' if n != 1 else ''}")
    else:
        print("last scan: never")
    t = _timers()
    if t:
        print(f"timers: scan={t['scan']} update={t['update']}")
    return 0


def _unit_dir() -> Path:
    for p in (Path("/usr/lib/systemd/user"), Path(__file__).resolve().parent.parent / "systemd"):
        if (p / "aurguard-scan.timer").exists():
            return p
    raise FileNotFoundError("systemd unit files not found")


def cmd_enable(args, cfg) -> int:
    src = _unit_dir()
    if src != Path("/usr/lib/systemd/user"):
        dest = Path.home() / ".config/systemd/user"
        dest.mkdir(parents=True, exist_ok=True)
        exe = shutil.which("aurguard") or f"{sys.executable} -m aurguard"
        for unit in src.glob("aurguard-*"):
            (dest / unit.name).write_text(unit.read_text().replace("/usr/bin/aurguard", exe))
        subprocess.run(["systemctl", "--user", "daemon-reload"])
    r = subprocess.run(["systemctl", "--user", "enable", "--now", "aurguard-update.timer", "aurguard-scan.timer"])
    if r.returncode == 0:
        print("enabled: DB update every 6h, scan daily (+ shortly after boot)")
    return r.returncode


def cmd_disable(args, cfg) -> int:
    return subprocess.run(["systemctl", "--user", "disable", "--now",
                           "aurguard-update.timer", "aurguard-scan.timer"]).returncode


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aurguard", description="Self-updating malware scanner for AUR packages")
    ap.add_argument("--version", action="version", version=f"aurguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan installed AUR packages")
    s.add_argument("package", nargs="*", help="only scan these packages")
    s.add_argument("--json", action="store_true")
    s.add_argument("--notify", action="store_true", help="desktop notification for high/critical findings")
    s.add_argument("--offline", action="store_true", help="blocklist only, no network")
    s.add_argument("--update", action="store_true", help="update threat DB first")
    s.add_argument("--all", action="store_true", help="include official repo packages in blocklist check")
    s.add_argument("-q", "--quiet", action="store_true")
    sub.add_parser("update", help="download latest threat DB")
    st = sub.add_parser("status", help="show DB version, last scan, timers")
    st.add_argument("--json", action="store_true")
    sub.add_parser("enable", help="enable automatic update+scan timers")
    sub.add_parser("disable", help="disable timers")
    args = ap.parse_args(argv)
    cfg = load_config()
    return {"scan": cmd_scan, "update": cmd_update, "status": cmd_status,
            "enable": cmd_enable, "disable": cmd_disable}[args.cmd](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
