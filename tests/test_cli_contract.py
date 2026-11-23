"""CLI contract tests (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, errors on stderr.

Uses the same offline fixtures as tests/test_dns_hygiene_checker.py (fake DoH server, loopback platform
servers): nothing here touches the real internet or real DNS.
"""
import json
import os
import socket
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import contract_support as cs  # noqa: E402
import test_dns_hygiene_checker as base  # noqa: E402

ROOT = os.path.dirname(HERE)
TOOL = base.TOOL
SCHEMA = cs.load_schema(ROOT, "dns-hygiene-checker")


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()


def cli(*args, doh=None):
    env = {"SSL_CERT_FILE": base.CA}
    return cs.run_cli(TOOL, ["--doh-url", doh or base.DOH_URL] + list(args), env=env, timeout=240)


def closed_port_url():
    s = socket.socket()
    s.bind((base.CUR[base.LIVE], 0))
    port = s.getsockname()[1]
    s.close()
    return "http://%s:%d/dns-query" % (base.CUR[base.LIVE], port)


CLEAN = ("clean.test", "--subdomains", "www")
FINDINGS = ("hyg.test", "--subdomains", base.SUBS)


class TestExitCodes(unittest.TestCase):
    def test_clean_is_0(self):
        rc, out, err = cli(*CLEAN)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("=== clean.test ===", out)

    def test_findings_is_1(self):
        rc, out, err = cli(*FINDINGS)
        self.assertEqual(rc, 1, out + err)

    def test_unknown_flag_is_2_with_empty_stdout(self):
        rc, out, err = cli("clean.test", "--no-such-flag")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("--no-such-flag", err)

    def test_missing_domain_is_2_with_empty_stdout(self):
        rc, out, err = cs.run_cli(TOOL, [])
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("domains", err)

    def test_only_discovered_without_source_is_2(self):
        rc, out, err = cli("clean.test", "--only-discovered")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("--only-discovered needs", err)

    def test_legacy_unreachable_resolver_is_2(self):
        rc, out, err = cli(*CLEAN, doh=closed_port_url())
        self.assertEqual(rc, 2, out + err)

    def test_legacy_unreadable_zone_file_is_2(self):
        rc, out, err = cli("disc.test", "--zone-file", os.path.join(base.TMP, "missing.zone"),
                           "--only-discovered", "--no-apex-checks")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("zone file discovery", out)

    def test_findings_beat_legacy_2(self):
        # a FAIL finding wins over an incomplete report
        rc, out, err = cli(*FINDINGS, "--zone-file", os.path.join(base.TMP, "missing.zone"))
        self.assertEqual(rc, 1, out + err)

    def test_internal_error_is_3_with_message_on_stderr(self):
        code = ("import sys, dns_hygiene_checker as m\n"
                "def boom(*a, **k):\n    raise KeyError('kaboom')\n"
                "m.audit = boom\n"
                "sys.exit(m.main(sys.argv[1:]))\n")
        for extra in ([], ["--json"], ["--quiet"]):
            p = subprocess.run([sys.executable, "-c", code, "clean.test"] + extra, cwd=ROOT,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
            self.assertEqual(p.stdout, "")
            self.assertIn("unexpected error: KeyError: 'kaboom'", p.stderr)
            self.assertNotIn("Traceback", p.stderr)


class TestJson(unittest.TestCase):
    def check(self, args, want_rc):
        rc, out, err = cli(*args, "--json")
        self.assertEqual(rc, want_rc, out + err)
        doc = json.loads(out)  # exactly one document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "dns-hygiene-checker")
        self.assertEqual(doc["version"], self.version())
        return doc

    def version(self):
        sys.path.insert(0, ROOT)
        import dns_hygiene_checker
        return dns_hygiene_checker.__version__

    def test_clean(self):
        doc = self.check(CLEAN, 0)
        self.assertEqual(list(doc["results"]), ["clean.test"])

    def test_findings(self):
        doc = self.check(FINDINGS, 1)
        levels = {f["level"] for f in doc["results"]["hyg.test"]}
        self.assertIn("FAIL", levels)

    def test_legacy_2_document(self):
        rc, out, err = cli(*CLEAN, "--json", doh=closed_port_url())
        self.assertEqual(rc, 2)
        doc = json.loads(out)
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], 2)
        self.assertIn("ERROR", [f["level"] for f in doc["results"]["clean.test"]])

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = cli("clean.test", "--json", "--bogus")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")

    def test_schema_rejects_missing_contract_key(self):
        doc = self.check(CLEAN, 0)
        for key in ("schema_version", "tool", "version", "exit_code", "results"):
            broken = dict(doc)
            del broken[key]
            self.assertTrue(cs.validate(broken, SCHEMA), key)


class TestQuiet(unittest.TestCase):
    def test_quiet_clean(self):
        for flag in ("--quiet", "-q"):
            rc, out, err = cli(*CLEAN, flag)
            self.assertEqual((rc, out), (0, ""), err)

    def test_quiet_findings_keep_exit_code(self):
        rc, out, err = cli(*FINDINGS, "--quiet")
        self.assertEqual((rc, out), (1, ""), err)

    def test_quiet_wins_over_json(self):
        rc, out, err = cli(*FINDINGS, "--quiet", "--json")
        self.assertEqual((rc, out), (1, ""), err)

    def test_quiet_hides_incomplete_report_but_keeps_exit_code(self):
        rc, out, err = cli(*CLEAN, "--quiet", doh=closed_port_url())
        self.assertEqual((rc, out), (2, ""), err)

    def test_not_quiet_prints_report(self):
        rc, out, err = cli(*CLEAN)
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main()
