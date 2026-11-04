"""Offline regression suite.

Runs without network access and without API keys. The sandbox tests need Linux
with unprivileged user namespaces; they skip cleanly elsewhere so CI on any
runner still exercises the pure-logic rules.
"""

from __future__ import annotations

import base64
import json
import shutil
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from airlock.canary import CanaryIndex, b64_variants, new_canary
from airlock.cli import detect_entry
from airlock.declared import _parse_simple_yaml, find_embedded_instructions, scan_tree
from airlock.engine import analyse
from airlock.engine import _domains
from airlock.sandbox import _sandbox_path, run_skill
from airlock.sarif import to_sarif

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

LINUX_NS = sys.platform.startswith("linux") and shutil.which("unshare") is not None


class TestCanary(unittest.TestCase):
    def test_unique_per_secret(self):
        self.assertNotEqual(new_canary("a"), new_canary("a"))

    def test_detects_literal_and_obfuscated(self):
        c = new_canary("aws_secret")
        ix = CanaryIndex(); ix.register("aws_secret", c)
        for payload in (c.encode(), base64.b64encode(c.encode()),
                        c.encode().hex().encode(), c.replace("_", "-").encode()):
            self.assertTrue(ix.scan_bytes("egress_tcp", payload, "t"), payload)

    def test_no_false_positive_on_unrelated_bytes(self):
        ix = CanaryIndex(); ix.register("s", new_canary("s"))
        self.assertEqual(ix.scan_bytes("egress_tcp", b"hello world nothing here", "t"), [])

    def test_hostname_safe_variants_exist(self):
        c = "alck_x_ab_cd"
        self.assertIn("alck-x-ab-cd", b64_variants(c))
        self.assertIn("alck.x.ab.cd", b64_variants(c))


class TestYamlSubset(unittest.TestCase):
    def test_universal_skill_format(self):
        y = _parse_simple_yaml(
            "name: s\nplatforms: [a, b]\npermissions:\n  files:\n    read:\n"
            "      - ~/.ssh/id_rsa\n      - ~/.env\n  network:\n    allow:\n"
            "      - api.example.com\n    deny: \"*\"\n  shell: false\n")
        self.assertEqual(y["name"], "s")
        self.assertEqual(y["platforms"], ["a", "b"])
        self.assertEqual(y["permissions"]["files"]["read"], ["~/.ssh/id_rsa", "~/.env"])
        self.assertEqual(y["permissions"]["network"]["allow"], ["api.example.com"])
        self.assertIs(y["permissions"]["shell"], False)

    def test_frontmatter_split(self):
        from airlock.declared import parse_frontmatter
        fm, body = parse_frontmatter("---\nname: x\n---\n# Body\n")
        self.assertEqual(fm, {"name": "x"})
        self.assertIn("# Body", body)


class TestDeclaration(unittest.TestCase):
    def test_parses_benign_fixture(self):
        d = scan_tree(FIXTURES / "01-benign-weather")
        self.assertEqual(d.name, "weather-summary")
        self.assertTrue(d.declares_domain("api.weather.gov"))
        self.assertFalse(d.declares_domain("collector.evil.test"))
        self.assertTrue(d.declares_path("/home/notes.md", "read"))
        self.assertFalse(d.declares_path("/home/.ssh/id_rsa", "read"))

    def test_catches_the_bcc_injection_static_scanners_miss(self):
        d = scan_tree(FIXTURES / "03-silent-bcc")
        reasons = {h["reason"] for h in find_embedded_instructions(d)}
        self.assertIn("hidden recipient", reasons)
        self.assertIn("model-directed note", reasons)
        self.assertIn("false-authority pretext", reasons)

    def test_benign_fixture_has_no_embedded_instructions(self):
        self.assertEqual(find_embedded_instructions(scan_tree(FIXTURES / "01-benign-weather")), [])

    def test_entry_detection(self):
        e, why = detect_entry(FIXTURES / "01-benign-weather")
        self.assertEqual(e, ["/bin/sh", "run.sh"])
        e, why = detect_entry(FIXTURES / "03-silent-bcc")
        self.assertTrue(e[-1].endswith("run.py"))


class TestHelpers(unittest.TestCase):
    def test_domains_ignores_loopback(self):
        net = [{"type": "dns_query", "qname": "evil.test"},
               {"type": "tcp_connect", "peer": "127.0.0.1"},
               {"type": "tls_clienthello", "sni": "a.example.com"}]
        self.assertEqual(sorted(_domains(net)), ["a.example.com", "evil.test"])

    def test_sandbox_path_translation(self):
        run = Path("/tmp/runX")
        self.assertEqual(_sandbox_path(run, "/tmp/runX/decoy/home/.ssh/id_rsa"),
                         "/home/.ssh/id_rsa")
        self.assertEqual(_sandbox_path(run, "/tmp/runX/scratch/x"), "/tmp/x")


@unittest.skipUnless(LINUX_NS, "needs Linux user namespaces")
class TestSandboxBehaviour(unittest.TestCase):
    """End-to-end: the rules that matter must fire on the fixtures and stay quiet
    on the honest ones. These are the regressions that would silently turn the
    tool into decoration."""

    def _scan(self, name, timeout=30):
        d = FIXTURES / name
        decl = scan_tree(d)
        entry, _ = detect_entry(d)
        r = run_skill(d, entry=entry, timeout=timeout)
        try:
            return analyse(r, decl), r
        finally:
            shutil.rmtree(r.run_dir, ignore_errors=True)

    def test_benign_skill_is_not_flagged(self):
        v, r = self._scan("01-benign-weather")
        self.assertTrue(r.ok)
        bad = [f for f in v.findings if f.severity in ("critical", "high", "medium")]
        self.assertEqual(bad, [], [f.title for f in bad])
        self.assertIn("api.weather.gov", v.observed_summary["domains"])
        self.assertFalse(v.trifecta["satisfied"])

    def test_credential_theft_is_confirmed(self):
        v, _ = self._scan("02-ssh-exfil")
        alk1 = [f for f in v.findings if f.rule_id == "ALK-001"]
        self.assertTrue(alk1)
        self.assertEqual(alk1[0].severity, "critical")
        self.assertEqual(alk1[0].ast, "AST01")
        self.assertIn("collector.evil.test", v.observed_summary["domains"])
        self.assertTrue(v.trifecta["satisfied"])
        self.assertGreaterEqual(v.risk_score, 70)

    def test_dns_tunnel_with_obfuscated_canary_is_confirmed(self):
        v, _ = self._scan("03-silent-bcc")
        alk1 = [f for f in v.findings if f.rule_id == "ALK-001"]
        self.assertTrue(alk1, "DNS-tunnelled canary was not detected")
        self.assertTrue(any("obfuscated" in f.title for f in alk1),
                        "the underscore-to-hyphen DNS encoding was not recognised")
        self.assertTrue(any(f.rule_id == "ALK-009" for f in v.findings))

    def test_rug_pull_changes_verdict_between_versions(self):
        v16, _ = self._scan("04-drift-v1.0.16")
        v17, _ = self._scan("05-drift-v1.0.17")
        self.assertNotIn("CRITICAL", v16.label)
        self.assertEqual(v17.label, "CRITICAL")
        self.assertIn("telemetry.postmark-analytics.test", v17.observed_summary["domains"])
        self.assertNotIn("telemetry.postmark-analytics.test", v16.observed_summary["domains"])

    def test_over_broad_manifest_is_informational_not_malicious(self):
        v, _ = self._scan("06-over-broad")
        self.assertNotIn(v.label, ("CRITICAL", "HIGH"))
        self.assertTrue(any(f.rule_id == "ALK-011" for f in v.findings),
                        "over-declaration should be reported")
        self.assertFalse(any(f.rule_id == "ALK-001" for f in v.findings))

    def test_real_home_is_never_mounted(self):
        """The isolation guarantee, asserted directly rather than assumed."""
        v, r = self._scan("01-benign-weather")
        self.assertNotIn(str(Path.home()), r.stdout)
        self.assertTrue(r.meta.get("coverage", {}).get("network_isolated"))

    def test_sarif_is_well_formed(self):
        v, _ = self._scan("02-ssh-exfil")
        s = to_sarif(v, target="fixtures/02-ssh-exfil")
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertTrue(run["results"])
        self.assertTrue(run["tool"]["driver"]["rules"])
        ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            self.assertIn(res["ruleId"], ids)
            self.assertIn(res["level"], ("error", "warning", "note", "none"))
        json.dumps(s)  # must be serialisable


if __name__ == "__main__":
    unittest.main(verbosity=2)
