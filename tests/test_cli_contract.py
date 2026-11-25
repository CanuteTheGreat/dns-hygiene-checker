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


class TestMainWrapperInProcess(unittest.TestCase):
    """main() is the exit-3 safety net around _main(). Called in-process (not through a child
    python) so the mutation run, which only sees calls made in the test process, covers it."""

    def run_main(self, argv, exc):
        import contextlib
        import io
        sys.path.insert(0, ROOT)
        import dns_hygiene_checker as m

        def boom(*a, **k):
            raise exc

        out, err = io.StringIO(), io.StringIO()
        old = m.audit
        m.audit = boom
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = m.main(argv)
        finally:
            m.audit = old
        return rc, out.getvalue(), err.getvalue()

    def test_unexpected_error_is_exit_3_with_exact_stderr_line(self):
        rc, out, err = self.run_main(["clean.test"], KeyError("kaboom"))
        self.assertEqual(rc, 3)
        self.assertEqual(out, "")
        self.assertEqual(err, "dns-hygiene-checker: unexpected error: KeyError: 'kaboom'\n")

    def test_error_text_uses_type_name_and_message(self):
        rc, out, err = self.run_main(["clean.test", "--json"], ValueError("bad thing"))
        self.assertEqual((rc, out), (3, ""))
        self.assertEqual(err, "dns-hygiene-checker: unexpected error: ValueError: bad thing\n")

    def test_quiet_does_not_hide_the_error_on_stderr(self):
        rc, out, err = self.run_main(["clean.test", "--quiet"], RuntimeError("x"))
        self.assertEqual((rc, out), (3, ""))
        self.assertEqual(err, "dns-hygiene-checker: unexpected error: RuntimeError: x\n")

    def test_argv_is_passed_through(self):
        # argv=None would fall back to sys.argv (pytest's own args) and exit 2 via argparse
        import dns_hygiene_checker as m  # noqa: F401
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["--no-such-flag"], KeyError("never reached"))
        self.assertEqual(cm.exception.code, 2)

    def test_non_exception_exits_are_not_swallowed(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_main(["clean.test"], KeyboardInterrupt())
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["clean.test"], SystemExit(7))
        self.assertEqual(cm.exception.code, 7)

    def test_success_returns_the_code_unchanged(self):
        import contextlib
        import io
        import dns_hygiene_checker as m
        old = m._main
        m._main = lambda argv=None: 41
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(m.main(["x"]), 41)
            self.assertEqual(err.getvalue(), "")
        finally:
            m._main = old


def squash(text):
    return " ".join(text.split())


HELP_USAGE = ("usage: dns-hygiene-checker [-h] [--version] [--subdomains SUBDOMAINS] [--json] [-q] "
              "[--doh-url DOH_URL] [--ct] [--zone-file FILE] [--cloudflare] [--only-discovered] "
              "[--no-apex-checks] domains [domains ...]")
HELP_OPTIONS = """positional arguments:
  domains               domain(s) to check, e.g. example.com
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --subdomains SUBDOMAINS
                        comma-separated list of subdomains to check instead of
                        the built-in common list
  --json                emit JSON instead of text
  -q, --quiet           print nothing on stdout (only the exit code and errors
                        on stderr)
  --doh-url DOH_URL     DNS-over-HTTPS JSON endpoint to query (default:
                        https://cloudflare-dns.com/dns-query; e.g.
                        https://dns.google/resolve)
  --ct                  also check every subdomain found in Certificate
                        Transparency logs (crt.sh, Cert Spotter)
  --zone-file FILE      also check every name in this BIND-style zone file
  --cloudflare          also check every record in the domain's Cloudflare
                        zone (CLOUDFLARE_API_TOKEN)
  --only-discovered     skip the built-in/--subdomains list; check only
                        discovered names
  --no-apex-checks      skip the MX/SRV/CAA/DNSSEC checks"""


class TestHelpBody(unittest.TestCase):
    def test_whole_help_body(self):
        # the whole --help text (usage, description, every option and its help/metavar), with the
        # 'options:' / 'optional arguments:' title (differs across Pythons) dropped
        rc, out, err = cs.run_cli(TOOL, ["--help"], env={"COLUMNS": "80"})
        self.assertEqual((rc, err), (0, ""))
        sys.path.insert(0, ROOT)
        import dns_hygiene_checker as m
        body = squash(out.replace("optional arguments:", "").replace("options:", ""))
        want = squash("%s %s %s" % (HELP_USAGE, m.__doc__, HELP_OPTIONS.replace("options:", "")))
        self.assertEqual(body, want)

    def test_hidden_test_hooks_stay_hidden_but_parse(self):
        rc, out, err = cs.run_cli(TOOL, ["--help"], env={"COLUMNS": "80"})
        for hook in ("--ct-url", "--certspotter-url", "--cloudflare-api"):
            self.assertNotIn(hook, out)


class TestMainInProcessBehaviour(unittest.TestCase):
    """_main() driven in-process with audit()/discover_*() stubbed: what it passes down, what it keeps."""

    def setUp(self):
        sys.path.insert(0, ROOT)
        import dns_hygiene_checker as m
        self.m = m
        self.saved = (m.audit, m.discover_ct, m.discover_zone_file, m.discover_cloudflare,
                      m.DOH_URL, m.CT_URL, m.CERTSPOTTER_URL, m.CLOUDFLARE_API)
        self.calls = []

        def fake_audit(domain, subs, **kw):
            self.calls.append((domain, list(subs), kw))
            return []

        m.audit = fake_audit

    def tearDown(self):
        m = self.m
        (m.audit, m.discover_ct, m.discover_zone_file, m.discover_cloudflare,
         m.DOH_URL, m.CT_URL, m.CERTSPOTTER_URL, m.CLOUDFLARE_API) = self.saved

    def main(self, argv):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        self.err = err
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = self.m.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_endpoint_defaults_are_kept_when_no_flag_is_given(self):
        m = self.m
        want = (m.DOH_URL, m.CT_URL, m.CERTSPOTTER_URL, m.CLOUDFLARE_API)
        self.assertTrue(all(isinstance(v, str) and v for v in want), want)
        self.assertEqual(self.main(["clean.test", "--subdomains", "www"])[0], 0)
        self.assertEqual((m.DOH_URL, m.CT_URL, m.CERTSPOTTER_URL, m.CLOUDFLARE_API), want)

    def test_endpoint_flags_override_the_globals(self):
        m = self.m
        self.main(["clean.test", "--subdomains", "www", "--doh-url", "http://d/x", "--ct-url", "http://c/",
                   "--certspotter-url", "http://s/", "--cloudflare-api", "http://f/"])
        self.assertEqual((m.DOH_URL, m.CT_URL, m.CERTSPOTTER_URL, m.CLOUDFLARE_API),
                         ("http://d/x", "http://c/", "http://s/", "http://f/"))

    def test_domain_is_normalised_before_audit(self):
        rc, out, err = self.main(["https://Clean.Test/", "http://Hyg.Test//", "  plain.test  ", "HTTP://x.test",
                                  "--subdomains", "www"])
        self.assertEqual([c[0] for c in self.calls], ["clean.test", "hyg.test", "plain.test", "http://x.test"])

    def test_only_trailing_slashes_are_stripped(self):
        # a name ending in a capital X must keep it (only "/" is stripped, then the name is lower-cased)
        self.main(["https://Hyg.TestX//", "--subdomains", "www"])
        self.assertEqual(self.calls[0][0], "hyg.testx")

    def test_only_discovered_without_source_error_text_is_exact(self):
        with self.assertRaises(SystemExit) as cm:
            self.main(["z.test", "--only-discovered"])
        self.assertEqual(cm.exception.code, 2)
        self.assertTrue(self.err.getvalue().endswith(
            "dns-hygiene-checker: error: --only-discovered needs --ct, --zone-file or --cloudflare\n"),
            self.err.getvalue())

    def test_only_discovered_skips_the_builtin_list(self):
        m = self.m
        m.discover_zone_file = lambda path, domain: ["a", "b"]
        self.main(["z.test", "--only-discovered", "--zone-file", "ignored"])
        self.assertEqual(self.calls[0][1], ["a", "b"])
        del self.calls[:]
        self.main(["z.test", "--zone-file", "ignored", "--subdomains", "x, y"])
        self.assertEqual(self.calls[0][1], ["x", "y", "a", "b"])
        del self.calls[:]
        self.main(["z.test", "--zone-file", "ignored"])
        self.assertEqual(self.calls[0][1][-2:], ["a", "b"])
        self.assertGreater(len(self.calls[0][1]), 10)

    def test_ct_discovery_failure_names_the_source(self):
        m = self.m

        def boom(domain):
            raise RuntimeError("crt.sh down")

        m.discover_ct = boom
        rc, out, err = self.main(["z.test", "--ct", "--subdomains", "www", "--json"])
        self.assertEqual(rc, 2)
        msg = json.loads(out)["results"]["z.test"][0]["message"]
        self.assertIn("(first: CT discovery: crt.sh down)", msg)

    def test_zone_file_and_cloudflare_failure_labels(self):
        m = self.m

        def boom(*a):
            raise OSError("nope")

        m.discover_zone_file = boom
        m.discover_cloudflare = boom
        rc, out, err = self.main(["z.test", "--zone-file", "f", "--cloudflare", "--subdomains", "www", "--json"])
        msg = json.loads(out)["results"]["z.test"][0]["message"]
        self.assertIn("2 lookup(s) failed", msg)
        self.assertIn("(first: zone file discovery: nope)", msg)
        self.assertEqual(self.m.RESOLVER_FAILURES[1], "Cloudflare discovery: nope")

    def test_discovery_notes_use_the_source_label(self):
        m = self.m
        m.discover_ct = lambda domain: (["a", "b"], "crt.sh")
        m.discover_zone_file = lambda path, domain: ["c"]
        m.discover_cloudflare = lambda domain: []
        rc, out, err = self.main(["z.test", "--ct", "--zone-file", "f", "--cloudflare", "--subdomains", "www", "--json"])
        msgs = [f["message"] for f in json.loads(out)["results"]["z.test"]]
        self.assertEqual(msgs[:3], ["crt.sh: 2 subdomain name(s) discovered", "zone file: 1 subdomain name(s) discovered",
                                    "Cloudflare: 0 subdomain name(s) discovered"])


if __name__ == "__main__":
    unittest.main()
