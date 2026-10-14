"""XDG locations and config loading."""
import os
import tomllib
from pathlib import Path

HOME = Path.home()
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", HOME / ".local/share")) / "aurguard"
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / "aurguard"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", HOME / ".cache")) / "aurguard"
CONFIG_FILE = Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config")) / "aurguard/config.toml"
BUNDLED = Path(__file__).parent / "data"

DEFAULT_FEED = "https://raw.githubusercontent.com/CHANGE-ME/aurguard/main/feed"


def load_config() -> dict:
    cfg = {"feed_url": DEFAULT_FEED, "fetch_pkgbuilds": True, "timeout": 15}
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            cfg.update(tomllib.load(f))
    cfg["feed_url"] = os.environ.get("AURGUARD_FEED", cfg["feed_url"]).rstrip("/")
    return cfg
