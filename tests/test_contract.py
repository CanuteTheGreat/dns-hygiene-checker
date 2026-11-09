"""Contract tests: pin the exact wording, levels and exit codes the tool prints (found from mutation
survivors: a changed word, level or argument of a lookup used to pass every `assertIn` test).

* TestGoldenCli runs the tool as a subprocess against the same fake DoH / platform / discovery servers as
  tests/test_dns_hygiene_checker.py and compares the whole JSON or text output with tests/golden_cli_data.py.
  Regenerate after an intended wording change with
      DHC_GOLDEN_OUT=/tmp/golden.json python -m unittest tests.test_contract   (then review the diff)
* TestOwnershipVerdict calls ownership_verdict() directly with a stubbed get_records().
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_dns_hygiene_checker as base  # noqa: E402  (its fixtures: DoH zone, platform HTTPS server, discovery server)
from golden_cli_data import GOLDEN  # noqa: E402

TOOL = base.TOOL


def load_tool():
    """The tool as the module `dns_hygiene_checker`: mutmut maps tests to mutants by that name (a copy loaded
    under another name via importlib.util is invisible to it, every mutant would survive)."""
    sys.path.insert(0, os.path.dirname(HERE))
    import dns_hygiene_checker
    return dns_hygiene_checker


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()


def cases():
    """name -> (args, setup/teardown callable or None); built when the fixture servers are up."""
    disc = ["--ct-url", base.DISC_URL + "/crtsh/", "--certspotter-url", base.DISC_URL + "/certspotter",
            "--cloudflare-api", base.DISC_URL + "/cf"]
    zone = os.path.join(base.TMP, "contract.zone")
    with open(zone, "w") as fh:
        fh.write("$ORIGIN disc.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 2 3 4 5\n"
                 "www IN A %s\n  IN AAAA ::1\nzone-only IN CNAME old-thing.example.net.\n"
                 "deep.sub.disc.test. IN A %s ; comment\n$ORIGIN lab\nbox IN A %s\n"
                 % (base.CUR[base.LIVE], base.CUR[base.LIVE], base.CUR[base.DEAD]))
    return {
        "hyg-json": (["hyg.test", "--subdomains", base.SUBS, "--json"], None),
        "hyg-text": (["hyg.test", "--subdomains", base.SUBS], None),
        "hyg-default-list": (["hyg.test", "--json"], None),
        "prov-json": (["prov.test", "--subdomains", base.PROV_SUBS, "--no-apex-checks", "--json"], None),
        "prov-text": (["prov.test", "--subdomains", base.PROV_SUBS, "--no-apex-checks"], None),
        "prov2-json": (["prov2.test", "--subdomains", "vc,az,azgone", "--no-apex-checks", "--json"], None),
        "prov2-text": (["prov2.test", "--subdomains", "vc,az,azgone", "--no-apex-checks"], None),
        "clean-json": (["clean.test", "--subdomains", "www", "--json"], None),
        "clean-text": (["clean.test", "--subdomains", "www,nope"], None),
        "clean-nothing-resolves": (["clean.test", "--subdomains", "nope,alsonope"], None),
        "signed-novalidate": (["signed-novalidate.test", "--subdomains", "x", "--json"], None),
        "wildcards-json": (["https://clean.test/", "wild.test", "badwild.test", "notls.test", "--subdomains", "www", "--json"], None),
        "wildcards-text": (["wild.test", "badwild.test", "notls.test", "--subdomains", "www"], None),
        "servfail": (["flaky.test", "--subdomains", "broken", "--json"], None),
        "servfail-text": (["flaky.test", "--subdomains", "broken"], None),
        "ct-ok": (["disc.test", "--json", "--ct", "--only-discovered", "--no-apex-checks"] + disc, "ct-ok"),
        "ct-ok-text": (["disc.test", "--ct", "--only-discovered", "--no-apex-checks"] + disc, "ct-ok"),
        "ct-fallback": (["disc.test", "--json", "--ct", "--only-discovered", "--no-apex-checks"] + disc, "ct-down"),
        "zone-file": (["disc.test", "--json", "--zone-file", zone, "--only-discovered", "--no-apex-checks"] + disc, None),
        "zone-file-text": (["disc.test", "--zone-file", zone, "--only-discovered", "--no-apex-checks"] + disc, None),
        "zone-file-missing": (["disc.test", "--json", "--zone-file", zone + ".nope", "--only-discovered"] + disc, None),
        "cloudflare": (["disc.test", "--json", "--cloudflare", "--only-discovered", "--no-apex-checks"] + disc, "cf-token"),
        "cloudflare-no-token": (["disc.test", "--json", "--cloudflare", "--no-apex-checks"] + disc, None),
        "cloudflare-bad-token": (["disc.test", "--json", "--cloudflare", "--only-discovered", "--no-apex-checks"] + disc, "cf-badtoken"),
        "ct-and-zone": (["disc.test", "--json", "--ct", "--zone-file", zone, "--only-discovered", "--no-apex-checks"] + disc, "ct-ok"),
    }


class Mode:
    """Server/env state for a case, undone afterwards."""

    def __init__(self, mode):
        self.mode = mode
        self.old = None

    def __enter__(self):
        m = self.mode
        if m == "ct-ok":
            base.CT_MODE["crtsh"] = "ok"
        elif m == "ct-down":
            base.CT_MODE["crtsh"] = "down"
        elif m == "cf-token":
            os.environ["CLOUDFLARE_API_TOKEN"] = "cf-test-token"
        elif m == "cf-badtoken":
            os.environ["CLOUDFLARE_API_TOKEN"] = "wrong"
        return self

    def __exit__(self, *exc):
        base.CT_MODE["crtsh"] = "ok"
        os.environ.pop("CLOUDFLARE_API_TOKEN", None)


def normalise(text):
    """Strip ports of the fixture servers, which differ every run."""
    import re
    text = text.replace(base.DISC_URL, "<DISC>").replace(base.DOH_URL, "<DOH>").replace(base.TMP, "<TMP>")
    text = re.sub(r"wildcard-probe-\d+", "wildcard-probe-N", text)
    text = text.replace(base.CUR[base.LIVE], base.LIVE).replace(base.CUR[base.DEAD], base.DEAD)
    return re.sub(r"127\.0\.0\.1:\d{4,5}", "127.0.0.1:<PORT>", text)


def capture_one(name):
    args, mode = cases()[name]
    zones = {}
    if mode == "ct-ok" or name == "ct-and-zone":
        # the CT-discovered name is an unclaimed Heroku app (as in the existing discovery test)
        zones[("takeover.disc.test", "CNAME")] = ["unclaimed-app.herokuapp.com."]
    base.ZONE.update(zones)
    try:
        with Mode(mode):
            p = base.run(*args)
    finally:
        for k in zones:
            base.ZONE.pop(k, None)
    return [p.returncode, normalise(p.stdout), normalise(p.stderr)]


GENERATED = {}


class TestGoldenCli(unittest.TestCase):
    """One test per case, each running its own CLI call: mutmut credits a function's calls to the test that
    was running, so a shared setUpClass capture would map everything to a single test that compares nothing."""
    maxDiff = None

    def test_every_case_is_pinned(self):
        self.assertEqual(sorted(cases()), sorted(GOLDEN))

    def check(self, name):
        got = capture_one(name)
        target = os.environ.get("DHC_GOLDEN_OUT")
        if target:
            GENERATED[name] = got
            with open(target, "w") as fh:
                json.dump(GENERATED, fh, indent=1, sort_keys=True)
        # stderr is not compared: under mutmut the tool runs in-process (tests/conftest.py), where the fixture
        # servers' own connection-reset tracebacks land on the same stream
        rc, out, _err = got
        want_rc, want_out, _want_err = GOLDEN[name]
        self.assertEqual(out, want_out, name)
        self.assertEqual(rc, want_rc, name)


def _add(name):
    setattr(TestGoldenCli, "test_golden_" + name.replace("-", "_"), lambda self, n=name: self.check(n))


for _name in GOLDEN:
    _add(_name)


class TestOwnershipVerdict(unittest.TestCase):
    """ownership_verdict() with get_records stubbed: every branch, exact text, and the lookups it makes."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_tool()

    def setUp(self):
        self.calls = []
        self.txt = {}
        mod = self.mod

        def fake(name, rtype):
            self.calls.append((name, rtype))
            return self.txt.get(name, []), 0

        self._real = mod.get_records
        mod.get_records = fake

    def tearDown(self):
        self.mod.get_records = self._real

    def test_not_a_verifying_host_is_none(self):
        self.assertIsNone(self.mod.ownership_verdict("a.x.test", "x.test", "app.herokuapp.com", "lead"))
        self.assertEqual(self.calls, [])

    def test_azure_with_verification_id_is_info(self):
        self.txt["asuid.a.x.test"] = ["abc"]
        got = self.mod.ownership_verdict("a.x.test", "x.test", "app.azurewebsites.net", "LEAD")
        self.assertEqual(got, ("INFO", "LEAD — Azure App Service: found a domain verification ID at asuid.a.x.test, "
                                       "so another Azure account should not be able to attach this hostname. "
                                       "Still remove the stale CNAME."))
        self.assertEqual(self.calls, [("asuid.a.x.test", "TXT")])

    def test_azure_without_verification_id_is_fail(self):
        got = self.mod.ownership_verdict("a.x.test", "x.test", "app.azurewebsites.net", "LEAD")
        self.assertEqual(got, ("FAIL", "LEAD — claimable: no TXT record at asuid.a.x.test, so nothing stops another "
                                       "Azure account from adding this hostname to an App Service app (the "
                                       "verification ID is optional). Remove the CNAME, or add the asuid TXT record "
                                       "from the app's custom domain page."))
        self.assertEqual(self.calls, [("asuid.a.x.test", "TXT")])

    def test_vercel_with_txt_is_info(self):
        self.txt["_vercel.x.test"] = ["vc-domain-verify=1"]
        got = self.mod.ownership_verdict("a.x.test", "x.test", "app.vercel.app", "LEAD", page=True)
        self.assertEqual(got, ("INFO", "LEAD — Vercel: found a TXT record at _vercel.x.test, so the domain looks "
                                       "verified and another account should not be able to attach it. "
                                       "Still remove the stale CNAME."))
        self.assertEqual(self.calls, [("_vercel.x.test", "TXT")])

    def test_vercel_without_txt_is_a_warning(self):
        got = self.mod.ownership_verdict("a.x.test", "x.test", "app.vercel.app", "LEAD", page=False)
        self.assertEqual(got, ("WARN", "LEAD — possibly claimable: Vercel blocks takeover if the domain is verified "
                                       "with a TXT record at _vercel.<domain>; check your account. "
                                       "Vercel only asks for it when the domain is already in another Vercel account "
                                       "or team. Remove the CNAME if nothing is published there."))
        self.assertEqual(self.calls, [("_vercel.x.test", "TXT")])

    def test_page_flag_adds_the_caveat_and_defaults_to_off(self):
        plain = self.mod.ownership_verdict("a.x.test", "x.test", "a.github.io", "LEAD")
        self.assertEqual(plain, self.mod.ownership_verdict("a.x.test", "x.test", "a.github.io", "LEAD", page=False))
        self.assertEqual(plain, ("WARN", "LEAD — possibly claimable: GitHub Pages blocks takeover if the domain is "
                                         "verified with a TXT record at _github-pages-challenge-<owner>.<domain>; "
                                         "check your account. The TXT name contains your GitHub user or organization "
                                         "name, so DNS alone can't confirm it. Remove the CNAME if nothing is "
                                         "published there."))
        seen = self.mod.ownership_verdict("a.x.test", "x.test", "a.github.io", "LEAD", page=True)
        self.assertEqual(seen, ("WARN", "LEAD — possibly claimable: GitHub Pages blocks takeover if the domain is "
                                        "verified with a TXT record at _github-pages-challenge-<owner>.<domain>; "
                                        "check your account. " + self.mod.PAGE_CAVEAT + " The TXT name contains your "
                                        "GitHub user or organization name, so DNS alone can't confirm it. Remove the "
                                        "CNAME if nothing is published there."))
        self.assertEqual(self.calls, [])

    def test_empty_note_leaves_no_double_space(self):
        # Azure has an empty note, but never reaches the generic text: use a table entry with an empty note
        saved = dict(self.mod.OWNERSHIP_VERIFIED)
        self.mod.OWNERSHIP_VERIFIED[".nonote.test"] = ("NoNote", "a thing", None, "")
        try:
            got = self.mod.ownership_verdict("a.x.test", "x.test", "a.nonote.test", "LEAD", page=False)
        finally:
            self.mod.OWNERSHIP_VERIFIED.clear()
            self.mod.OWNERSHIP_VERIFIED.update(saved)
        self.assertEqual(got, ("WARN", "LEAD — possibly claimable: NoNote blocks takeover if the domain is verified "
                                       "with a thing; check your account. Remove the CNAME if nothing is published "
                                       "there."))



class TestHelpersAndWire(unittest.TestCase):
    """In-process tests of the small helpers and the exact HTTP/DoH requests, with the network calls stubbed
    or recorded (mutation survivors: headers, query strings, timeouts, retry counts, error texts)."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_tool()

    def setUp(self):
        from unittest import mock
        self.mock = mock
        del self.mod.RESOLVER_FAILURES[:]
        self.addCleanup(self.mod.RESOLVER_FAILURES.clear)
        saved = (self.mod.DOH_URL, self.mod.CT_URL, self.mod.CERTSPOTTER_URL, self.mod.CLOUDFLARE_API)
        self.mod.DOH_URL = base.DOH_URL
        self.addCleanup(lambda: setattr_all(self.mod, saved))
        self.doh_queries, self.platform_reqs, self.disc_reqs = [], [], []
        self.overrides = {}
        orig_doh, orig_plat, orig_disc = base.DohHandler.do_GET, base.PlatformHandler.do_GET, base.DiscoveryHandler.do_GET
        outer = self

        def doh(h):
            from urllib.parse import parse_qs, urlparse
            outer.doh_queries.append((parse_qs(urlparse(h.path).query), dict(h.headers)))
            return orig_doh(h)

        def plat(h):
            outer.platform_reqs.append((h.requestline, dict(h.headers)))
            host = (h.headers.get("Host") or "").split(":")[0]
            if host in outer.overrides:
                code, data = outer.overrides[host]
                h.send_response(code)
                h.send_header("Content-Length", str(len(data)))
                h.send_header("Connection", "close")
                h.end_headers()
                h.wfile.write(data)
                return
            return orig_plat(h)

        def disc(h):
            outer.disc_reqs.append((h.path, dict(h.headers)))
            return orig_disc(h)

        base.DohHandler.do_GET, base.PlatformHandler.do_GET, base.DiscoveryHandler.do_GET = doh, plat, disc
        self.addCleanup(lambda: setattr_all_handlers(orig_doh, orig_plat, orig_disc))

    # -- suffix_match / relative_names / txt_value
    def test_suffix_match(self):
        sm = self.mod.suffix_match
        sufs = {".github.io": 1, ".s3-website": 2, "bare.example": 3}
        self.assertEqual(sm("A.Github.IO.", sufs), ".github.io")
        self.assertEqual(sm("github.io", sufs), ".github.io")
        self.assertIsNone(sm("notgithub.io", sufs))
        self.assertEqual(sm("bare.example", sufs), "bare.example")
        self.assertEqual(sm("x.bare.example.", sufs), "bare.example")
        self.assertEqual(sm("b.s3-website-us-east-1.amazonaws.com", sufs), ".s3-website")
        self.assertEqual(sm("s3-website-eu-west-1.amazonaws.com", sufs), ".s3-website")
        self.assertIsNone(sm("xs3-website.example.com", sufs))
        self.assertIsNone(sm("example.com", sufs))
        # only dots are stripped from a suffix: a leading X is part of it (hosts are lowercased, so no match)
        self.assertIsNone(sm("foo.example", {"Xfoo.example": 1}))
        self.assertEqual(sm("a.xfoo.example", {"..xfoo.example": 1}), "..xfoo.example")

    def test_relative_names(self):
        names = [" WWW.Disc.Test. ", "*.Wild.disc.test", "a b.disc.test", "disc.test", "x.other.test", "*.disc.test",
                 "deep.sub.disc.test", "www.disc.test"]
        self.assertEqual(self.mod.relative_names(names, "disc.test"), ["deep.sub", "wild", "www"])
        self.assertEqual(self.mod.relative_names([], "disc.test"), [])

    def test_txt_value(self):
        tv = self.mod.txt_value
        self.assertEqual(tv('"v=spf1 a" " -all"'), "v=spf1 a -all")
        self.assertEqual(tv('"say \\"hi\\""'), 'say \\"hi\\"')
        self.assertEqual(tv("plain text"), "plain text")
        self.assertEqual(tv(""), "")
        self.assertEqual(tv('"one"'), "one")

    # -- DoH-backed helpers
    def test_get_ad_asks_for_the_soa_with_the_do_bit(self):
        self.assertEqual(self.mod.get_ad("clean.test"), (True, 0))
        q, headers = self.doh_queries[-1]
        self.assertEqual((q["name"], q["type"], q["do"]), (["clean.test"], ["SOA"], ["1"]))
        self.assertEqual(headers.get("Accept"), "application/dns-json")
        self.assertEqual(self.mod.get_ad("hyg.test"), (False, 0))
        self.assertEqual(self.mod.get_ad("nothing.invalid"), (False, 3))
        self.assertEqual(self.mod.get_ad("broken.flaky.test"), (False, 2))

    def test_get_ad_without_a_resolver_is_unknown(self):
        self.mod.DOH_URL = "http://%s:1/dns-query" % base.CUR[base.LIVE]
        self.assertEqual(self.mod.get_ad("clean.test"), (None, None))
        self.assertEqual(len(self.mod.RESOLVER_FAILURES), 1)
        self.assertTrue(self.mod.RESOLVER_FAILURES[0].startswith("clean.test/SOA: "), self.mod.RESOLVER_FAILURES)

    def test_resolves_tries_a_then_aaaa(self):
        base.ZONE[("v6only.hyg.test", "AAAA")] = ["::1"]
        self.addCleanup(base.ZONE.pop, ("v6only.hyg.test", "AAAA"))
        self.assertIs(self.mod.resolves("www.hyg.test"), True)
        self.assertEqual([q["type"] for q, _ in self.doh_queries], [["A"]])
        del self.doh_queries[:]
        self.assertIs(self.mod.resolves("v6only.hyg.test"), True)
        self.assertEqual([q["type"] for q, _ in self.doh_queries], [["A"], ["AAAA"]])
        self.assertIs(self.mod.resolves("nothing.invalid"), False)

    def test_get_records_filters_by_type_and_reports_servfail(self):
        self.assertEqual(self.mod.get_records("www.hyg.test", "A"), ([base.CUR[base.LIVE]], 0))
        self.assertEqual(self.mod.get_records("nothing.invalid", "A"), ([], 3))
        self.assertEqual(self.mod.get_records("broken.flaky.test", "A"), ([], 2))
        self.assertEqual(self.mod.RESOLVER_FAILURES, ["broken.flaky.test/A: SERVFAIL"])

    def test_check_port_open(self):
        import socket
        srv = socket.socket()
        srv.bind((base.CUR[base.LIVE], 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        self.assertIs(self.mod.check_port_open(base.CUR[base.LIVE], srv.getsockname()[1]), True)
        closed = socket.socket()
        closed.bind((base.CUR[base.LIVE], 0))
        port = closed.getsockname()[1]
        closed.close()
        self.assertIs(self.mod.check_port_open(base.CUR[base.LIVE], port), False)

    def test_connect_timeouts(self):
        calls = []

        def refuse(addr, *a, **kw):
            calls.append((addr, a, kw))
            raise OSError("refused")

        with self.mock.patch.object(self.mod.socket, "create_connection", refuse):
            self.assertIs(self.mod.check_port_open("192.0.2.1", 80), False)
            self.assertIs(self.mod.check_port_open("192.0.2.1", 80, timeout=2), False)
            self.assertEqual(self.mod.http_claim_check("x.herokuapp.com", ["192.0.2.7"]), (None, None))
            self.assertIsNone(self.mod.wildcard_cert_verdict("probe.example.test", ["192.0.2.8"]))
        self.assertEqual(calls, [(("192.0.2.1", 80), (), {"timeout": 4}),
                                 (("192.0.2.1", 80), (), {"timeout": 2}),
                                 (("192.0.2.7", 443), (), {"timeout": 8}),
                                 (("192.0.2.8", 443), (), {"timeout": 6})])
        self.assertIsNone(self.mod.wildcard_cert_verdict("probe.example.test", []))

    # -- http_claim_check against the platform server
    def claim(self, host):
        return self.mod.http_claim_check(host, (base.CUR[base.LIVE],))

    def test_http_claim_check_request_and_verdicts(self):
        self.assertEqual(self.claim("unclaimed-app.herokuapp.com"),
                         (True, 'HTTP 404 with unclaimed-resource fingerprint ("no such app") on unclaimed-app.herokuapp.com'))
        line, headers = self.platform_reqs[-1]
        self.assertEqual(line, "GET / HTTP/1.1")
        self.assertEqual({k: headers[k] for k in ("Host", "User-Agent", "Accept", "Connection")},
                         {"Host": "unclaimed-app.herokuapp.com", "User-Agent": "dns-hygiene-checker/1.0",
                          "Accept": "text/html", "Connection": "close"})
        self.assertEqual(self.claim("my-app.herokuapp.com"),
                         (False, "HTTP 200, no unclaimed-resource fingerprint on my-app.herokuapp.com"))
        self.assertEqual(self.mod.http_claim_check("unclaimed-app.herokuapp.com", ()), (None, None))
        self.assertEqual(self.mod.http_claim_check("example.org", (base.CUR[base.LIVE],)), (None, None))
        self.assertEqual(self.mod.http_claim_check("x.herokuapp.com", (base.CUR[base.DEAD],)), (None, None))

    def test_http_claim_check_body_handling(self):
        self.overrides["upper.herokuapp.com"] = (404, b"<p>NO SUCH APP</p>")
        self.assertEqual(self.claim("upper.herokuapp.com")[0], True)
        self.overrides["bytes.herokuapp.com"] = (404, b"\xff\xfe<p>no such app</p>")
        self.assertEqual(self.claim("bytes.herokuapp.com")[0], True)
        self.overrides["late.herokuapp.com"] = (404, b"x" * 20000 + b"no such app")
        self.assertEqual(self.claim("late.herokuapp.com"),
                         (False, "HTTP 404, no unclaimed-resource fingerprint on late.herokuapp.com"))
        self.overrides["early.herokuapp.com"] = (404, b"x" * 8000 + b"no such app" + b"y" * 20000)
        self.assertEqual(self.claim("early.herokuapp.com")[0], True)
        self.overrides["ok.herokuapp.com"] = (503, b"busy")
        self.assertEqual(self.claim("ok.herokuapp.com"),
                         (False, "HTTP 503, no unclaimed-resource fingerprint on ok.herokuapp.com"))

    # -- _http_json
    def test_http_json_request_and_decoding(self):
        seen = {}

        class Resp:
            def __init__(self, data):
                self.data = data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self.data

        def urlopen(req, *a, **kw):
            seen["req"], seen["a"], seen["kw"] = req, a, kw
            return Resp(seen["data"])

        seen["data"] = b'["caf\xc3\xa9", "bad\xff"]'
        with self.mock.patch.object(self.mod.urllib.request, "urlopen", urlopen):
            self.assertEqual(self.mod._http_json("http://x.test/p?q=1"), ["caf\u00e9", "bad\ufffd"])
            req = seen["req"]
            self.assertEqual(req.full_url, "http://x.test/p?q=1")
            self.assertEqual(sorted(req.header_items()),
                             [("Accept", "application/json"), ("User-agent", "dns-hygiene-checker/%s" % self.mod.__version__)])
            self.assertEqual((seen["a"], seen["kw"]), ((), {"timeout": 30}))
            self.mod._http_json("http://x.test/", {"Authorization": "Bearer t"}, timeout=5)
            self.assertEqual(sorted(seen["req"].header_items()),
                             [("Accept", "application/json"), ("Authorization", "Bearer t"),
                              ("User-agent", "dns-hygiene-checker/%s" % self.mod.__version__)])
            self.assertEqual(seen["kw"], {"timeout": 5})

    # -- discover_ct
    def stub_http_json(self, answers):
        calls = []

        def fake(url, headers=None, timeout=30):
            calls.append((url, headers, timeout))
            a = answers[len(calls) - 1]
            if isinstance(a, Exception):
                raise a
            return a

        return calls, self.mock.patch.object(self.mod, "_http_json", fake)

    def test_discover_ct_crtsh_first_with_exact_url(self):
        calls, patch = self.stub_http_json([[{"name_value": "a b.d.test\nc.d.test"}, {"name_value": "WWW.d.test"}, {}]])
        with patch:
            self.assertEqual(self.mod.discover_ct("d.test"), (["c", "www"], "crt.sh"))
        self.assertEqual(calls, [(self.mod.CT_URL + "?q=%25.d.test&output=json", None, 60)])

    def test_discover_ct_retries_crtsh_once_then_cert_spotter(self):
        calls, patch = self.stub_http_json([ValueError("a"), ValueError("b"),
                                            [{"dns_names": ["x.d.test", "*.y.d.test"]}, {}, {"dns_names": ["x.d.test"]}]])
        with patch:
            self.assertEqual(self.mod.discover_ct("d.test"), (["x", "y"], "Cert Spotter"))
        crt = self.mod.CT_URL + "?q=%25.d.test&output=json"
        spot = self.mod.CERTSPOTTER_URL + "?domain=d.test&include_subdomains=true&expand=dns_names"
        self.assertEqual(calls, [(crt, None, 60), (crt, None, 60), (spot, None, 60)])

    def test_discover_ct_error_lists_every_attempt(self):
        calls, patch = self.stub_http_json([ValueError("a"), OSError("b"), RuntimeError("c")])
        with patch, self.assertRaises(RuntimeError) as cm:
            self.mod.discover_ct("d.test")
        self.assertEqual(str(cm.exception), "crt.sh: a; crt.sh: b; Cert Spotter: c")
        self.assertEqual(len(calls), 3)

    def test_discover_ct_second_crtsh_attempt_can_succeed(self):
        calls, patch = self.stub_http_json([ValueError("a"), [{"name_value": "ok.d.test"}]])
        with patch:
            self.assertEqual(self.mod.discover_ct("d.test"), (["ok"], "crt.sh"))
        self.assertEqual(len(calls), 2)

    # -- discover_cloudflare
    def test_discover_cloudflare_urls_header_and_paging(self):
        calls, patch = self.stub_http_json([
            {"result": [{"id": "z9", "name": "d.test"}]},
            {"result": [{"name": "a.d.test"}, {"name": "d.test"}, {}], "result_info": {"total_pages": "3"}},
            {"result": None, "result_info": {"total_pages": 3}},
            {"result": [{"name": "WWW.d.test."}], "result_info": {"page": 3}},
        ])
        with self.mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "tok"}), patch:
            self.assertEqual(self.mod.discover_cloudflare("d.test"), ["a", "www"])
        api = self.mod.CLOUDFLARE_API
        h = {"Authorization": "Bearer tok"}
        self.assertEqual(calls, [(api + "/zones?name=d.test", h, 30),
                                 (api + "/zones/z9/dns_records?per_page=500&page=1", h, 30),
                                 (api + "/zones/z9/dns_records?per_page=500&page=2", h, 30),
                                 (api + "/zones/z9/dns_records?per_page=500&page=3", h, 30)])

    def test_discover_cloudflare_errors(self):
        with self.mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": ""}), self.assertRaises(RuntimeError) as cm:
            self.mod.discover_cloudflare("d.test")
        self.assertEqual(str(cm.exception), "--cloudflare needs CLOUDFLARE_API_TOKEN (a token with Zone:DNS:Read)")
        calls, patch = self.stub_http_json([{"result": []}])
        with self.mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "t"}), patch, self.assertRaises(RuntimeError) as cm:
            self.mod.discover_cloudflare("d.test")
        self.assertEqual(str(cm.exception), "no Cloudflare zone named d.test visible to this token")
        calls, patch = self.stub_http_json([{}])
        with self.mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "t"}), patch, self.assertRaises(RuntimeError):
            self.mod.discover_cloudflare("d.test")

    # -- discover_zone_file
    def zone(self, text):
        path = os.path.join(base.TMP, "unit.zone")
        with open(path, "w") as fh:
            fh.write(text)
        return self.mod.discover_zone_file(path, "d.test")

    def test_zone_file_origins_owners_and_comments(self):
        self.assertEqual(self.zone("www IN A 1.2.3.4\n\n; only a comment\n   ; indented comment\nmail IN A 1.2.3.5 ; c\n"),
                         ["mail", "www"])
        self.assertEqual(self.zone("$TTL 300\n$INCLUDE other.zone\n@ IN SOA ns h 1 2 3 4 5\na IN A 1.1.1.1\n  IN AAAA ::1\n"),
                         ["a"])
        self.assertEqual(self.zone("$origin lab\nbox IN A 1.1.1.1\n$ORIGIN x.d.test.\n@ IN A 2.2.2.2\nsub IN A 3.3.3.3\n"),
                         ["box.lab", "sub.x", "x"])
        self.assertEqual(self.zone("a IN A 1.1.1.1\n\n\nb IN A 1.1.1.2\n"), ["a", "b"])
        self.assertEqual(self.zone("full.d.test. IN A 1.1.1.1\nother.example. IN A 2.2.2.2\n@ IN A 3.3.3.3\n"), ["full"])
        self.assertEqual(self.zone("  IN A 9.9.9.9\nnext IN A 1.1.1.1\n  IN TXT \"x\"\n"), ["next"])
        self.assertEqual(self.zone("a IN A 1.1.1.1 ; c1 ; c2\nb IN TXT \"v;x\"\n"), ["a", "b"])
        self.assertEqual(self.zone("$ORIGIN d.test.\nwww IN A 1.1.1.1\n"), ["www"])
        self.assertEqual(self.zone(""), [])


def setattr_all(mod, saved):
    mod.DOH_URL, mod.CT_URL, mod.CERTSPOTTER_URL, mod.CLOUDFLARE_API = saved


def setattr_all_handlers(doh, plat, disc):
    base.DohHandler.do_GET, base.PlatformHandler.do_GET, base.DiscoveryHandler.do_GET = doh, plat, disc


class TestWildcardCertVerdict(unittest.TestCase):
    """wildcard_cert_verdict()'s TLS outcomes with a fake socket and context (no network)."""

    def run_verdict(self, wrap_exc=None):
        from unittest import mock
        mod = load_tool()
        raw = mock.MagicMock()

        class Ctx:
            def wrap_socket(self, sock, server_hostname=None):
                self.args = (sock, server_hostname)
                if wrap_exc is not None:
                    raise wrap_exc
                return mock.MagicMock()

        ctx = Ctx()
        with mock.patch.object(mod.socket, "create_connection", return_value=raw), \
                mock.patch.object(mod.ssl, "create_default_context", return_value=ctx):
            out = mod.wildcard_cert_verdict("probe.example.test", ["192.0.2.8"])
        self.assertEqual(ctx.args, (raw, "probe.example.test"))
        raw.close.assert_called_once_with()
        return out

    def test_valid(self):
        self.assertIs(self.run_verdict(), True)

    def test_verify_message_is_the_reason(self):
        import ssl
        e = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] boom")
        e.verify_message = "Hostname mismatch, certificate is not valid for 'probe.example.test'."
        self.assertEqual(self.run_verdict(e), "Hostname mismatch, certificate is not valid for 'probe.example.test'.")

    def test_no_verify_message_falls_back_to_str(self):
        import ssl
        for msg in (None, ""):
            e = ssl.SSLCertVerificationError(1, "bad cert chain")
            e.verify_message = msg
            self.assertEqual(self.run_verdict(e), str(e))
            self.assertNotEqual(self.run_verdict(e), "None")
        e = ssl.SSLCertVerificationError(1, "bad cert chain")
        vars(e).pop("verify_message", None)
        self.assertEqual(self.run_verdict(e), str(e))

    def test_handshake_failure(self):
        import ssl
        self.assertEqual(self.run_verdict(ssl.SSLError("boom")), "TLS handshake failed: %s" % ssl.SSLError("boom"))
        self.assertEqual(self.run_verdict(OSError("reset")), "TLS handshake failed: reset")


if __name__ == "__main__":
    unittest.main()
