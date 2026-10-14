import shutil
import subprocess


def send(title: str, body: str, critical: bool = True) -> None:
    if not shutil.which("notify-send"):
        return
    subprocess.run(["notify-send", "-a", "aurguard", "-i", "security-high",
                    "-u", "critical" if critical else "normal", title, body], check=False)
