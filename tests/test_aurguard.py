import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from aurguard import archlists, db, rules, scanner, upstream
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


FEED_XML = """<?xml version="1.0"?><rss><channel>
<item><title>[PRQ#90001] Deletion Request for evil-bin</title>
<description>someone [1] filed a deletion request for evil-bin [2]:

This package downloads a malicious binary that steals browser data.
[2] https://aur.archlinux.org/pkgbase/evil-bin/</description>
<link>https://lists.archlinux.org/x/1</link><pubDate>Wed, 14 Oct 2026 23:05:35 +0000</pubDate></item>
<item><title>[PRQ#90002] Deletion Request for opendeck-bin</title>
<description>Obsolete, now in [Extra].</description>
<link>https://lists.archlinux.org/x/2</link><pubDate>Wed, 14 Oct 2026 23:05:35 +0000</pubDate></item>
<item><title>Malware found in AUR</title>
<description>Please check https://aur.archlinux.org/packages/bad-git and remove it, it contains a trojan.</description>
<link>https://lists.archlinux.org/x/3</link><pubDate>Wed, 14 Oct 2026 20:00:00 +0000</pubDate></item>
</channel></rss>"""


class ArchListTests(unittest.TestCase):
    def test_parse_requests(self):
        r = archlists.parse_feed(FEED_XML, "aur-requests")
        self.assertEqual([x["package"] for x in r], ["evil-bin"])  # benign deletion ignored

    def test_parse_general_urls(self):
        r = archlists.parse_feed(FEED_XML, "aur-general")
        self.assertIn("bad-git", [x["package"] for x in r])

    def test_update_accumulates_and_scan_flags(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            new, errs = archlists.update(data_dir=d, get=lambda url, t: FEED_XML)
            self.assertEqual(errs, [])
            again, _ = archlists.update(data_dir=d, get=lambda url, t: "<rss><channel></channel></rss>")
            self.assertEqual(again, 0)
            state = archlists.load(d)
            self.assertTrue(any(r["package"] == "evil-bin" for r in state["reports"]))  # kept after feed rolled over
            f = scanner.check_archlists([Package("evil-bin", "1")], state, set())
            self.assertEqual(f[0].severity, "high")


class CloudHistoryTests(unittest.TestCase):
    def test_merges_reports_collected_while_offline(self):
        cloud = json.dumps({"reports": [{"package": "missed-bin", "list": "aur-requests",
                                         "title": "t", "link": "L", "date": "2026-10-01"}]})
        empty = "<rss><channel></channel></rss>"
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            new, errs = archlists.update(data_dir=d, cloud_url="C",
                                         get=lambda url, t: cloud if url == "C" else empty)
            self.assertEqual((new, errs), (1, []))
            self.assertEqual(archlists.load(d)["reports"][0]["package"], "missed-bin")


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
