import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from aurguard import db, rules, scanner, upstream
from aurguard.inventory import Package, parse

FIX = Path(__file__).parent / "fixtures"
FEED = Path(__file__).parent.parent / "feed"


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.compiled = rules.compile_rules(json.loads((FEED / "rules.json").read_text()))

    def test_malicious_flagged(self):
        hits = rules.apply(self.compiled, {"PKGBUILD": (FIX / "malicious.PKGBUILD").read_text()})
        ids = {h.rule_id for h in hits}
        self.assertTrue({"PIPE-TO-SHELL", "B64-EXEC", "DISCORD-CDN", "SHELL-RC-WRITE"} <= ids, ids)

    def test_benign_clean(self):
        self.assertEqual(rules.apply(self.compiled, {"PKGBUILD": (FIX / "benign.PKGBUILD").read_text()}), [])

    def test_bad_regex_ignored(self):
        self.assertEqual(rules.compile_rules({"rules": [{"id": "x", "pattern": "(", "severity": "high"}]}), [])


class BlocklistTests(unittest.TestCase):
    def test_known_malware(self):
        threats = json.loads((FEED / "threats.json").read_text())
        f = scanner.check_blocklist([Package("librewolf-fix-bin", "1-1"), Package("yay", "12")], threats)
        self.assertEqual([x.package for x in f], ["librewolf-fix-bin"])
        self.assertEqual(f[0].severity, "critical")

    def test_version_pinned(self):
        threats = json.loads((FEED / "threats.json").read_text())
        self.assertEqual(scanner.check_blocklist([Package("acroread", "9.5.5-9")], threats), [])
        self.assertEqual(len(scanner.check_blocklist([Package("acroread", "9.5.5-8")], threats)), 1)

    def test_bad_maintainer(self):
        f = scanner.check_metadata([Package("x", "1")], {"x": {"Maintainer": "evil", "FirstSubmitted": 0}},
                                   set(), {"evil"})
        self.assertEqual(f[0].severity, "critical")


class CampaignTests(unittest.TestCase):
    UP = {"campaigns": [{"id": "x", "display": "June 2026", "window": {"start": "2026-06-09", "end": "2026-06-14"},
                         "packages": ["hijacked-git"], "accounts": [], "iocs": []}]}

    def test_installed_during_attack_is_critical(self):
        f = scanner.check_campaigns([Package("hijacked-git", "1")], self.UP, {"hijacked-git": 1781200000}, set())
        self.assertEqual(f[0].severity, "critical")

    def test_installed_before_attack_is_medium(self):
        f = scanner.check_campaigns([Package("hijacked-git", "1")], self.UP, {"hijacked-git": 1700000000}, set())
        self.assertEqual(f[0].severity, "medium")

    def test_parse_list(self):
        self.assertEqual(upstream.parse_list("```\n# c\nfoo-bin\n\nbar # note\nnot a pkg\n```"), ["foo-bin", "bar"])

    def test_fetch(self):
        files = {"I/data/campaigns.json": json.dumps({"campaigns": [{"id": "a", "type": "aur", "lists": ["l.txt"],
                                                                      "sources": {}}]}),
                 "I/l.txt": "evil-bin\n"}
        d = upstream.fetch(get=lambda url, t: files[url], base="I/")
        self.assertEqual(d["campaigns"][0]["packages"], ["evil-bin"])


class InventoryTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse("yay 12.4-1\nfoo-bin 2:1.0-3\n\n"),
                         [Package("yay", "12.4-1"), Package("foo-bin", "2:1.0-3")])


class UpdateTests(unittest.TestCase):
    def _feed(self, version, tamper=False):
        files = {"threats.json": b'{"packages": [{"name": "newbad"}]}', "rules.json": b'{"rules": []}'}
        manifest = {"version": version, "sha256": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}}
        if tamper:
            files["threats.json"] = b'{"packages": []}'
        files["manifest.json"] = json.dumps(manifest).encode()
        return lambda url, timeout: files[url.rsplit("/", 1)[1]]

    def test_update_installs_new_feed(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            changed, m = db.update("http://feed", data_dir=d, fetch=self._feed(999))
            self.assertTrue(changed)
            self.assertEqual(db.load_threats(d)["packages"][0]["name"], "newbad")
            changed, _ = db.update("http://feed", data_dir=d, fetch=self._feed(999))
            self.assertFalse(changed)

    def test_tampered_feed_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            with self.assertRaises(db.UpdateError):
                db.update("http://feed", data_dir=d, fetch=self._feed(999, tamper=True))
            self.assertFalse((d / "threats.json").exists())


if __name__ == "__main__":
    unittest.main()
