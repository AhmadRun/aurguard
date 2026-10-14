"""AUR RPC + PKGBUILD fetching."""
import json
import urllib.parse
import urllib.request

from . import __version__

RPC = "https://aur.archlinux.org/rpc/v5/info"
CGIT = "https://aur.archlinux.org/cgit/aur.git/plain/{file}?h={pkgbase}"


def _get(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"aurguard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def info(names: list[str], timeout: int = 15) -> dict[str, dict]:
    """Return {name: rpc_result}. Packages missing from result are not (or no longer) on the AUR."""
    result = {}
    for i in range(0, len(names), 150):
        chunk = names[i:i + 150]
        qs = urllib.parse.urlencode([("arg[]", n) for n in chunk])
        data = json.loads(_get(f"{RPC}?{qs}", timeout))
        for r in data.get("results", []):
            result[r["Name"]] = r
    return result


def fetch_file(pkgbase: str, file: str, timeout: int = 15) -> str | None:
    try:
        return _get(CGIT.format(file=file, pkgbase=urllib.parse.quote(pkgbase)), timeout).decode("utf-8", "replace")
    except Exception:
        return None


def fetch_sources(pkgbase: str, timeout: int = 15) -> dict[str, str]:
    """PKGBUILD plus any .install file it references."""
    files = {}
    pkgbuild = fetch_file(pkgbase, "PKGBUILD", timeout)
    if pkgbuild is None:
        return files
    files["PKGBUILD"] = pkgbuild
    for line in pkgbuild.splitlines():
        line = line.strip()
        if line.startswith("install="):
            name = line.split("=", 1)[1].strip("'\" ").replace("$pkgname", pkgbase).replace("${pkgname}", pkgbase)
            content = fetch_file(pkgbase, name, timeout)
            if content:
                files[name] = content
    return files
