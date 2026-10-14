"""Local threat database and the auto-updater that keeps it current."""
import hashlib
import json
import os
import tempfile
import urllib.request
from pathlib import Path

from . import __version__
from .paths import BUNDLED, DATA_DIR

FILES = ("threats.json", "rules.json")


class UpdateError(Exception):
    pass


def _fetch(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"aurguard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _load(name: str, data_dir: Path = DATA_DIR) -> dict:
    p = data_dir / name
    if not p.exists():
        p = BUNDLED / name
    return json.loads(p.read_text())


def load_threats(data_dir: Path = DATA_DIR) -> dict:
    return _load("threats.json", data_dir)


def load_rules(data_dir: Path = DATA_DIR) -> dict:
    return _load("rules.json", data_dir)


def local_manifest(data_dir: Path = DATA_DIR) -> dict:
    return _load("manifest.json", data_dir)


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def update(feed_url: str, timeout: int = 15, data_dir: Path = DATA_DIR, fetch=_fetch) -> tuple[bool, dict]:
    """Download the feed if newer. Returns (changed, manifest). Verifies sha256 of every file."""
    try:
        remote = json.loads(fetch(f"{feed_url}/manifest.json", timeout))
    except Exception as e:
        raise UpdateError(f"cannot fetch manifest: {e}") from e
    current = local_manifest(data_dir)
    if remote.get("version", 0) <= current.get("version", 0) and (data_dir / "manifest.json").exists():
        return False, remote

    blobs = {}
    for name in FILES:
        try:
            blob = fetch(f"{feed_url}/{name}", timeout)
        except Exception as e:
            raise UpdateError(f"cannot fetch {name}: {e}") from e
        want = remote.get("sha256", {}).get(name)
        got = hashlib.sha256(blob).hexdigest()
        if want != got:
            raise UpdateError(f"checksum mismatch for {name} (expected {want}, got {got})")
        json.loads(blob)  # must be valid JSON
        blobs[name] = blob
    # only install once everything verified
    for name, blob in blobs.items():
        _atomic_write(data_dir / name, blob)
    _atomic_write(data_dir / "manifest.json", json.dumps(remote, indent=2).encode())
    return True, remote
