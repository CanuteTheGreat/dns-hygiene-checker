"""End-to-end tests for dns_hygiene_checker.py.

The tool runs unmodified as a subprocess. Its DNS view comes from a local
DNS-over-HTTPS JSON server (same wire format as cloudflare-dns.com/dns-query,
selected with --doh-url), and the addresses in that zone point at a real local
HTTPS server on 127.0.0.1:443 that plays the cloud platforms (an unclaimed
Heroku app's "no such app" page, a claimed app) and serves the TLS
certificates the wildcard check inspects (signed by a throwaway CA trusted
through SSL_CERT_FILE). 127.0.0.2 has nothing listening: a dead address.

Binding port 443 needs root, which the CI container (ci/run-tests.sh) has.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as HTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "dns_hygiene_checker.py")
TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15, "NS": 2, "SRV": 33, "DS": 43, "CAA": 257, "SOA": 6}
LIVE, DEAD = "127.0.0.1", "127.0.0.2"

# (name, type) -> list of record data; names not listed are NXDOMAIN unless a
# wildcard below matches; SERVFAIL names answer Status 2.
ZONE = {
    ("www.hyg.test", "A"): [LIVE],
    ("dead.hyg.test", "A"): [DEAD],
    ("mixed.hyg.test", "A"): [LIVE, DEAD],
    ("gone.hyg.test", "CNAME"): ["old-thing.example.net."],
    ("bucket.hyg.test", "CNAME"): ["forgotten-bucket.s3.amazonaws.com."],
    ("takeover.hyg.test", "CNAME"): ["unclaimed-app.herokuapp.com."],
    ("unclaimed-app.herokuapp.com", "A"): [LIVE],
    ("claimed.hyg.test", "CNAME"): ["my-app.herokuapp.com."],
    ("my-app.herokuapp.com", "A"): [LIVE],
    ("cdn.hyg.test", "CNAME"): ["d111abc.cloudfront.net."],
    ("d111abc.cloudfront.net", "A"): [LIVE],
    # claimable service with no HTTP fingerprint rule, live: INFO
    ("files.hyg.test", "CNAME"): ["hygfiles.blob.core.windows.net."],
    ("hygfiles.blob.core.windows.net", "A"): [LIVE],
    # CloudFront verifies domain ownership (can-i-take-over-xyz: not vulnerable): dangling = WARN, not FAIL
    ("oldcdn.hyg.test", "CNAME"): ["d999gone.cloudfront.net."],
    # suffixes match on label boundaries: notgithub.io is not GitHub Pages
    ("lookalike.hyg.test", "CNAME"): ["pages.notgithub.io."],
    ("blog.hyg.test", "CNAME"): ["hyg-blog.example.org."],
    ("hyg-blog.example.org", "A"): [LIVE],
    # SPF published as two character-strings; the includes span both
    ("hyg.test", "TXT"): ['"v=spf1 include:_spf.good.test " "include:gone-mail.test include:nospf.test -all"',
                          '"google-site-verification=abc"'],
    ("_spf.good.test", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 -all"'],
    ("nospf.test", "TXT"): ['"some-other-verification=1"'],
    ("www.clean.test", "A"): [LIVE],
    # dangling NS delegation, a half-dangling one, MX/SRV targets
    ("retired-zone.hyg.test", "NS"): ["ns1.expired-dns-host.test.", "ns2.expired-dns-host.test."],
    ("half.hyg.test", "NS"): ["ns1.good-dns.test.", "ns.gone-dns.test."],
    ("ns1.good-dns.test", "A"): [LIVE],
    ("hyg.test", "MX"): ["10 mx1.hyg.test.", "20 old-mx.retired-mail.test."],
    ("mx1.hyg.test", "A"): [LIVE],
    ("mail2.hyg.test", "A"): [LIVE],
    ("mail2.hyg.test", "MX"): ["10 nowhere.hyg-mail.test."],
    ("zone-only.disc.test", "CNAME"): ["old-thing.example.net."],
    ("box.lab.disc.test", "A"): [DEAD],
    ("_sip._tls.hyg.test", "SRV"): ["100 1 443 sipdir.gone-provider.test."],
    ("_autodiscover._tcp.hyg.test", "SRV"): ["0 0 443 mx1.hyg.test."],
    # CAA + DNSSEC: clean.test has both, hyg.test neither
    ("clean.test", "CAA"): ['0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:sec@clean.test"'],
    ("clean.test", "DS"): ["2371 13 2 0123456789ABCDEF"],
    ("signed-novalidate.test", "DS"): ["1 13 2 00"],
}
# Provider classes for an "unclaimed" answer (TestProviderClasses): hosts that let the owner verify the
# domain, and hosts with no such protection. Every target resolves to LIVE unless noted.
PROVIDER_HOSTS = {
    # verification exists, nothing in DNS we can look up (GitHub's TXT name holds the unknown owner)
    "gh": "ghsite.github.io", "nl": "nlsite.netlify.app", "pa": "pasite.pantheonsite.io",
    # verification exists and its TXT record is observable: Vercel at _vercel.<domain>, Azure at asuid.<host>
    "vc": "vcapp.vercel.app", "az": "azapp.azurewebsites.net",
    # no ownership check in the provider's docs
    "hk": "hkapp.herokuapp.com", "sg": "sgsite.surge.sh", "rd": "rtdproj.readthedocs.io", "gs": "gsblog.ghost.io",
}
for _k, _target in PROVIDER_HOSTS.items():
    ZONE[(_k + ".prov.test", "CNAME")] = [_target + "."]
    ZONE[(_target, "A")] = [LIVE]
# the same Vercel/Azure records, on a domain that published the verification TXT
ZONE[("vc.prov2.test", "CNAME")] = ["vcapp.vercel.app."]
ZONE[("_vercel.prov2.test", "TXT")] = ['"vc-domain-verify=vc.prov2.test,abc123"']
ZONE[("az.prov2.test", "CNAME")] = ["azapp.azurewebsites.net."]
ZONE[("asuid.az.prov2.test", "TXT")] = ['"0123456789ABCDEF"']
# deleted app: the target no longer resolves at all (Azure's classic case) / a GitHub Pages target that is gone
ZONE[("azgone.prov.test", "CNAME")] = ["deleted-app.azurewebsites.net."]
ZONE[("azgone.prov2.test", "CNAME")] = ["deleted-app.azurewebsites.net."]
ZONE[("ghgone.prov.test", "CNAME")] = ["gone-user.github.io."]
# a provider that verifies, whose target answers normally (claimed): stays OK
ZONE[("ghok.prov.test", "CNAME")] = ["claimed-user.github.io."]
ZONE[("claimed-user.github.io", "A")] = [LIVE]
# what each platform shows for a hostname nobody has claimed
UNCLAIMED_PAGES = {
    "unclaimed-app.herokuapp.com": "Heroku | No such app",
    "ghsite.github.io": "<h1>404</h1> There isn't a GitHub Pages site here.",
    "vcapp.vercel.app": "The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND",
    "nlsite.netlify.app": "Not Found - Request ID: 01H0TEST",
    "pasite.pantheonsite.io": "404 error unknown site!",
    "azapp.azurewebsites.net": "Microsoft Azure Web App - Error 404",
    "hkapp.herokuapp.com": "Heroku | No such app",
    "sgsite.surge.sh": "project not found",
    "rtdproj.readthedocs.io": "The link you have followed or the URL that you entered does not exist.",
    "gsblog.ghost.io": "Site unavailable",
}
VALIDATED = {"clean.test"}
EXISTS_EMPTY = {"prov.test", "prov2.test", "nospf.test", "clean.test", "hyg.test", "wild.test", "badwild.test", "notls.test",
                "signed-novalidate.test", "disc.test"}
WILDCARDS = {"wild.test": LIVE, "badwild.test": LIVE, "notls.test": DEAD}
SERVFAIL = {"broken.flaky.test"}


class DohHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        name, rtype = q["name"][0].rstrip("."), q["type"][0]
        answers, status = [], 3
        if name in SERVFAIL:
            status = 2
        elif any(k[0] == name for k in ZONE) or name in EXISTS_EMPTY:
            status = 0
            answers = ZONE.get((name, rtype), [])
        else:
            for parent, ip in WILDCARDS.items():
                if name.endswith("." + parent):
                    status = 0
                    answers = [ip] if rtype == "A" else []
        body = json.dumps({"Status": status, "AD": name in VALIDATED, "Answer": [
            {"name": name + ".", "type": TYPES[rtype], "TTL": 60, "data": d} for d in answers]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


CT_DATA = [{"name_value": "takeover.disc.test\n*.disc.test"}, {"name_value": "disc.test\nwww.disc.test"},
           {"name_value": "WWW.disc.test"}, {"name_value": "evil.disc.test.attacker.example"}]
CF_RECORDS = [[{"name": "cf-only.disc.test"}, {"name": "disc.test"}], [{"name": "page2.disc.test"}]]
CT_MODE = {"crtsh": "ok"}


class DiscoveryHandler(BaseHTTPRequestHandler):
    """Plays crt.sh, Cert Spotter and the Cloudflare API."""

    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/crtsh/":
            if CT_MODE["crtsh"] != "ok":
                return self.reply(502, {"error": "bad gateway"})
            assert q["q"] == ["%.disc.test"] and q["output"] == ["json"]
            return self.reply(200, CT_DATA)
        if u.path == "/certspotter":
            assert q["include_subdomains"] == ["true"] and q["expand"] == ["dns_names"]
            return self.reply(200, [{"dns_names": ["spotted.disc.test", "*.disc.test"]}])
        if self.headers.get("Authorization") != "Bearer cf-test-token":
            return self.reply(403, {"success": False})
        if u.path == "/cf/zones":
            return self.reply(200, {"result": [{"id": "z1", "name": q["name"][0]}]})
        if u.path == "/cf/zones/z1/dns_records":
            page = int(q["page"][0])
            return self.reply(200, {"result": CF_RECORDS[page - 1], "result_info": {"page": page, "total_pages": 2}})
        self.reply(404, {})


class PlatformHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host in UNCLAIMED_PAGES:
            code, body = 404, "<html><body>%s</body></html>" % UNCLAIMED_PAGES[host]
        else:
            code, body = 200, "<html><body>hello from %s</body></html>" % host
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


def openssl(*args):
    subprocess.run(["openssl"] + list(args), check=True, capture_output=True)


def leaf(name, san):
    key, csr, crt, ext = (os.path.join(TMP, name + s) for s in (".key", ".csr", ".crt", ".ext"))
    with open(ext, "w") as f:
        f.write("subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" % san)
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=" + name)
    openssl("x509", "-req", "-in", csr, "-CA", CA, "-CAkey", CA_KEY, "-CAcreateserial", "-days", "2",
            "-out", crt, "-extfile", ext)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


def setUpModule():
    global TMP, CA, CA_KEY, DOH, DOH_URL, HTTPS, DISC
    TMP = tempfile.mkdtemp()
    CA, CA_KEY = os.path.join(TMP, "ca.pem"), os.path.join(TMP, "ca.key")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", CA_KEY, "-out", CA, "-days", "2",
            "-subj", "/CN=dns-hygiene test CA", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    contexts = {"wild": leaf("wild", "DNS:*.wild.test,DNS:wild.test"),
                "badwild": leaf("badwild", "DNS:www.badwild.test"),
                "default": leaf("platform", "DNS:*.herokuapp.com,DNS:localhost")}

    def pick(sock, server_name, _ctx):
        name = server_name or ""
        if name.endswith(".wild.test"):
            sock.context = contexts["wild"]
        elif name.endswith(".badwild.test"):
            sock.context = contexts["badwild"]

    default = contexts["default"]
    default.sni_callback = pick
    HTTPS = HTTPServer((LIVE, 443), PlatformHandler)
    HTTPS.socket = default.wrap_socket(HTTPS.socket, server_side=True)
    threading.Thread(target=HTTPS.serve_forever, daemon=True).start()

    global DISC_URL
    DISC = HTTPServer((LIVE, 0), DiscoveryHandler)
    DISC_URL = "http://%s:%d" % DISC.server_address
    threading.Thread(target=DISC.serve_forever, daemon=True).start()

    DOH = HTTPServer((LIVE, 0), DohHandler)
    DOH_URL = "http://%s:%d/dns-query" % DOH.server_address
    threading.Thread(target=DOH.serve_forever, daemon=True).start()


def tearDownModule():
    # close the listening sockets too: mutation testing runs the suite several times in one process
    for srv in (DOH, HTTPS, DISC):
        srv.shutdown()
        srv.server_close()
    shutil.rmtree(TMP, ignore_errors=True)


def run(*args, doh=None):
    env = dict(os.environ, SSL_CERT_FILE=CA)
    return subprocess.run([sys.executable, TOOL, "--doh-url", doh or DOH_URL] + list(args),
                          capture_output=True, text=True, env=env, timeout=240)


def by_name(results, domain):
    out = {}
    for f in results[domain]:
        out.setdefault(f["name"], []).append(f)
    return out


SUBS = ("www,dead,mixed,gone,bucket,takeover,claimed,cdn,blog,doesnotexist,retired-zone,half,mail2,"
        "files,oldcdn,lookalike")


class TestChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = run("hyg.test", "--subdomains", SUBS, "--json")
        cls.res = json.loads(cls.p.stdout)
        cls.f = by_name(cls.res, "hyg.test")

    def one(self, name, level):
        got = self.f.get(name, [])
        self.assertEqual([x["level"] for x in got], [level], json.dumps(got, indent=1))
        return got[0]["message"]

    def test_fail_exit_code(self):
        self.assertEqual(self.p.returncode, 1, self.p.stderr)

    def test_live_a_record(self):
        self.assertIn("responsive on 80/443", self.one("www.hyg.test", "OK"))

    def test_dead_a_record(self):
        self.assertIn("nothing answers on 80/443", self.one("dead.hyg.test", "WARN"))

    def test_partly_dead_a_record_set(self):
        msg = self.one("mixed.hyg.test", "WARN")
        self.assertIn("%s does not answer" % DEAD, msg)

    def test_dangling_cname_non_claimable(self):
        msg = self.one("gone.hyg.test", "WARN")
        self.assertIn("old-thing.example.net does NOT resolve", msg)

    def test_dangling_cname_claimable_is_fail(self):
        msg = self.one("bucket.hyg.test", "FAIL")
        self.assertIn("claimable cloud service", msg)

    def test_unclaimed_platform_fingerprint_is_fail(self):
        msg = self.one("takeover.hyg.test", "FAIL")
        self.assertIn('HTTP 404 with unclaimed-resource fingerprint ("no such app")', msg)

    def test_claimed_platform_is_ok(self):
        msg = self.one("claimed.hyg.test", "OK")
        self.assertIn("currently claimed", msg)
        self.assertIn("HTTP 200", msg)

    def test_claimable_without_fingerprint_rule_is_info(self):
        self.assertIn("claimable cloud service pattern", self.one("files.hyg.test", "INFO"))

    def test_ownership_verifying_service_is_not_claimable(self):
        # CloudFront is "Not vulnerable" on can-i-take-over-xyz: live is a plain OK, dangling a WARN
        self.assertIn("resolves fine", self.one("cdn.hyg.test", "OK"))
        msg = self.one("oldcdn.hyg.test", "WARN")
        self.assertIn("CloudFront verifies domain ownership", msg)
        self.assertNotIn("subdomain-takeover", msg)

    def test_suffixes_match_on_label_boundaries(self):
        msg = self.one("lookalike.hyg.test", "WARN")
        self.assertIn("pages.notgithub.io does NOT resolve", msg)
        self.assertNotIn("claimable", msg)

    def test_plain_cname_ok(self):
        self.assertIn("resolves fine", self.one("blog.hyg.test", "OK"))

    def test_nonexistent_subdomain_not_reported(self):
        self.assertNotIn("doesnotexist.hyg.test", self.f)

    def test_spf_includes_across_split_txt_strings(self):
        spf = [x["message"] for x in self.f.get("SPF", [])]
        self.assertEqual(len(spf), 2, spf)
        self.assertTrue(any("include:gone-mail.test does NOT resolve" in m for m in spf), spf)
        self.assertTrue(any("include:nospf.test exists but publishes no SPF record" in m for m in spf), spf)
        self.assertFalse(any("_spf.good.test" in m for m in spf), spf)

    def test_no_wildcard_no_wildcard_finding(self):
        self.assertFalse(any("Wildcard" in x["message"] for x in self.res["hyg.test"]))

    def test_dangling_ns_delegation(self):
        msg = self.one("retired-zone.hyg.test", "FAIL")
        self.assertIn("NS delegation to ns1.expired-dns-host.test, ns2.expired-dns-host.test", msg)
        self.assertIn("ns.gone-dns.test", self.one("half.hyg.test", "WARN"))

    def test_dangling_mx_and_srv(self):
        apex = [x["message"] for x in self.f["hyg.test"] if x["level"] == "WARN"]
        self.assertTrue(any("MX -> old-mx.retired-mail.test does NOT resolve" in m for m in apex), apex)
        self.assertFalse(any("mx1.hyg.test" in m for m in apex), apex)
        sub = [x["message"] for x in self.f["mail2.hyg.test"]]
        self.assertTrue(any("MX -> nowhere.hyg-mail.test does NOT resolve" in m for m in sub), sub)
        self.assertEqual([x["level"] for x in self.f["_sip._tls.hyg.test"]], ["WARN"])
        self.assertNotIn("_autodiscover._tcp.hyg.test", self.f)

    def test_caa_and_dnssec_missing(self):
        self.assertIn("no CAA record on hyg.test", self.one("CAA", "WARN"))
        self.assertIn("not DNSSEC-signed", self.one("DNSSEC", "WARN"))

    def test_findings_sorted_by_severity(self):
        order = {"FAIL": 0, "WARN": 1, "INFO": 2, "OK": 3}
        levels = [order[x["level"]] for x in self.res["hyg.test"]]
        self.assertEqual(levels, sorted(levels))


class TestWildcard(unittest.TestCase):
    def wildcard_finding(self, domain):
        p = run(domain, "--subdomains", "www", "--json")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return [x for x in json.loads(p.stdout)[domain] if "Wildcard" in x["message"]]

    def test_wildcard_with_covering_cert_ok(self):
        f = self.wildcard_finding("wild.test")
        self.assertEqual([x["level"] for x in f], ["OK"], f)

    def test_wildcard_with_non_covering_cert_warns(self):
        f = self.wildcard_finding("badwild.test")
        self.assertEqual([x["level"] for x in f], ["WARN"], f)
        self.assertIn("does not cover it", f[0]["message"])

    def test_wildcard_without_tls_is_info(self):
        f = self.wildcard_finding("notls.test")
        self.assertEqual([x["level"] for x in f], ["INFO"], f)
        self.assertIn("nothing answered TLS", f[0]["message"])


class TestApexAndDiscovery(unittest.TestCase):
    def test_caa_and_dnssec_present(self):
        res = json.loads(run("clean.test", "--subdomains", "www", "--json").stdout)
        f = by_name(res, "clean.test")
        self.assertEqual(f["CAA"][0]["level"], "OK")
        self.assertIn("letsencrypt.org", f["CAA"][0]["message"])
        self.assertIn("issuewild: 1", f["CAA"][0]["message"])
        self.assertNotIn("no iodef", f["CAA"][0]["message"])
        self.assertEqual(f["DNSSEC"][0]["level"], "OK")
        f = by_name(json.loads(run("signed-novalidate.test", "--subdomains", "x", "--json").stdout), "signed-novalidate.test")
        self.assertEqual(f["DNSSEC"][0]["level"], "INFO")
        p = run("clean.test", "--subdomains", "www", "--json", "--no-apex-checks")
        self.assertNotIn("CAA", by_name(json.loads(p.stdout), "clean.test"))

    def disc(self, *args):
        p = run("disc.test", "--json", "--ct-url", DISC_URL + "/crtsh/", "--certspotter-url", DISC_URL + "/certspotter",
                "--cloudflare-api", DISC_URL + "/cf", *args)
        return p, json.loads(p.stdout)["disc.test"]

    def checked_names(self, findings):
        return {x["name"] for x in findings}

    def test_ct_discovery(self):
        CT_MODE["crtsh"] = "ok"
        ZONE[("takeover.disc.test", "CNAME")] = ["unclaimed-app.herokuapp.com."]
        try:
            p, f = self.disc("--ct", "--only-discovered", "--no-apex-checks")
        finally:
            del ZONE[("takeover.disc.test", "CNAME")]
        self.assertEqual(p.returncode, 1, f)  # the CT-discovered name is an unclaimed Heroku app
        self.assertIn("takeover.disc.test", self.checked_names(f))
        notes = [x["message"] for x in f if x["name"] == "disc.test" and x["level"] == "INFO"]
        self.assertIn("crt.sh: 2 subdomain name(s) discovered", notes)  # takeover + www (deduped, no apex/wildcard)

    def test_ct_falls_back_to_cert_spotter(self):
        CT_MODE["crtsh"] = "down"
        try:
            p, f = self.disc("--ct", "--only-discovered", "--no-apex-checks")
        finally:
            CT_MODE["crtsh"] = "ok"
        self.assertEqual(p.returncode, 0, f)
        self.assertIn("Cert Spotter: 1 subdomain name(s) discovered", [x["message"] for x in f])

    def test_zone_file_and_cloudflare(self):
        zone = os.path.join(TMP, "disc.zone")
        with open(zone, "w") as fh:
            fh.write("$ORIGIN disc.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 2 3 4 5\n"
                     "www IN A 127.0.0.1\n  IN AAAA ::1\nzone-only IN CNAME old-thing.example.net.\n"
                     "deep.sub.disc.test. IN A 127.0.0.1 ; comment\n$ORIGIN lab\nbox IN A 127.0.0.2\n")
        p, f = self.disc("--zone-file", zone, "--only-discovered", "--no-apex-checks")
        self.assertIn("zone file: 4 subdomain name(s) discovered", [x["message"] for x in f])
        self.assertIn("zone-only.disc.test", self.checked_names(f))
        self.assertIn("box.lab.disc.test", self.checked_names(f))
        os.environ["CLOUDFLARE_API_TOKEN"] = "cf-test-token"
        try:
            p, f = self.disc("--cloudflare", "--only-discovered", "--no-apex-checks")
        finally:
            del os.environ["CLOUDFLARE_API_TOKEN"]
        self.assertIn("Cloudflare: 2 subdomain name(s) discovered", [x["message"] for x in f])
        p, f = self.disc("--cloudflare", "--no-apex-checks")
        self.assertEqual(p.returncode, 2)  # no token: discovery failed, report incomplete
        self.assertTrue(any("CLOUDFLARE_API_TOKEN" in x["message"] for x in f if x["level"] == "ERROR"))

    def test_only_discovered_needs_a_source(self):
        p = run("disc.test", "--only-discovered")
        self.assertEqual(p.returncode, 2)


class TestCli(unittest.TestCase):
    def test_text_output_and_clean_exit(self):
        p = run("clean.test", "--subdomains", "www,nope")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("=== clean.test ===", p.stdout)
        self.assertIn("[OK   ] www.clean.test: A -> 127.0.0.1 (responsive on 80/443)", p.stdout)

    def test_default_subdomain_list(self):
        p = run("hyg.test", "--json")  # built-in list has www/blog/cdn but none of the takeover names
        f = by_name(json.loads(p.stdout), "hyg.test")
        for name in ("www.hyg.test", "blog.hyg.test", "cdn.hyg.test"):
            self.assertIn(name, f)
        self.assertNotIn("takeover.hyg.test", f)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_nothing_resolves_message(self):
        p = run("clean.test", "--subdomains", "nope,alsonope")
        self.assertEqual(p.returncode, 0)
        self.assertIn("no subdomains from the checked list currently resolve", p.stdout)

    def test_multiple_domains_and_url_forms(self):
        p = run("https://clean.test/", "wild.test", "--subdomains", "www", "--json")
        self.assertEqual(sorted(json.loads(p.stdout)), ["clean.test", "wild.test"])

    def test_unreachable_resolver_is_error_not_clean(self):
        s = socket.socket()
        s.bind((LIVE, 0))
        port = s.getsockname()[1]
        s.close()
        p = run("clean.test", "--subdomains", "www", doh="http://%s:%d/dns-query" % (LIVE, port))
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("[ERROR] clean.test:", p.stdout)
        self.assertIn("INCOMPLETE", p.stdout)
        self.assertNotIn("nothing to report", p.stdout)

    def test_servfail_is_error(self):
        p = run("flaky.test", "--subdomains", "broken", "--json")
        self.assertEqual(p.returncode, 2, p.stdout)
        levels = [x["level"] for x in json.loads(p.stdout)["flaky.test"]]
        self.assertIn("ERROR", levels)

    def test_version(self):
        p = subprocess.run([sys.executable, TOOL, "--version"], capture_output=True, text=True)
        self.assertRegex(p.stdout, r"^dns-hygiene-checker \d+\.\d+\.\d+$")

    def test_help_lists_options(self):
        p = subprocess.run([sys.executable, TOOL, "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        for opt in ("--subdomains", "--json", "--doh-url", "--ct", "--zone-file", "--cloudflare", "--only-discovered"):
            self.assertIn(opt, p.stdout)


if __name__ == "__main__":
    unittest.main()


PROV_SUBS = "gh,nl,pa,vc,az,hk,sg,rd,gs,azgone,ghgone,ghok"


class TestProviderClasses(unittest.TestCase):
    """An \"unclaimed\" answer is a real takeover risk only where the provider doesn't let the domain owner
    verify the domain. Each provider class gets its own verdict (docs checked 2026-10-28, see the tool's
    OWNERSHIP_VERIFIED table)."""

    @classmethod
    def setUpClass(cls):
        cls.f1 = by_name(json.loads(run("prov.test", "--subdomains", PROV_SUBS, "--no-apex-checks", "--json").stdout), "prov.test")
        cls.p2 = run("prov2.test", "--subdomains", "vc,az,azgone", "--no-apex-checks", "--json")
        cls.f2 = by_name(json.loads(cls.p2.stdout), "prov2.test")

    def one(self, found, name, level):
        got = found.get(name, [])
        self.assertEqual([x["level"] for x in got], [level], json.dumps(got, indent=1))
        return got[0]["message"]

    # -- owner verification exists, can't be looked up: WARN \"possibly claimable\", never a flat \"claimable\"
    def possibly(self, sub, provider, mechanism):
        msg = self.one(self.f1, sub + ".prov.test", "WARN")
        self.assertIn("possibly claimable: %s blocks takeover if the domain is verified with %s; check your account"
                      % (provider, mechanism), msg)
        self.assertNotIn("this IS an active subdomain-takeover", msg)
        return msg

    def test_github_pages_possibly_claimable_txt_name_has_unknown_owner(self):
        msg = self.possibly("gh", "GitHub Pages", "a TXT record at _github-pages-challenge-<owner>.<domain>")
        self.assertIn("there isn't a github pages site here", msg)
        self.assertIn("can't confirm", msg)

    def test_netlify_possibly_claimable_and_marked_unconfirmed(self):
        msg = self.possibly("nl", "Netlify", "Netlify's domain ownership checks")
        self.assertIn("unconfirmed", msg)

    def test_pantheon_possibly_claimable_and_notes_pre_enforcement_exemption(self):
        msg = self.possibly("pa", "Pantheon", "an ownership check (a DNS TXT value or a file upload)")
        self.assertIn("exempt", msg)

    # -- Vercel: the TXT at _vercel.<domain> is observable
    def test_vercel_without_txt_is_possibly_claimable(self):
        msg = self.possibly("vc", "Vercel", "a TXT record at _vercel.<domain>")
        self.assertIn("already in another Vercel account", msg)

    def test_vercel_with_txt_is_info_not_a_failure(self):
        msg = self.one(self.f2, "vc.prov2.test", "INFO")
        self.assertIn("found a TXT record at _vercel.prov2.test", msg)
        self.assertNotIn("claimable", msg)

    # -- Azure: asuid.<host> is observable, so absence is a real finding
    def test_azure_without_asuid_is_claimable(self):
        msg = self.one(self.f1, "az.prov.test", "FAIL")
        self.assertIn("claimable: no TXT record at asuid.az.prov.test", msg)

    def test_azure_with_asuid_is_info(self):
        msg = self.one(self.f2, "az.prov2.test", "INFO")
        self.assertIn("found a domain verification ID at asuid.az.prov2.test", msg)
        self.assertNotIn("claimable", msg)

    def test_deleted_azure_app_nxdomain_checks_asuid_too(self):
        self.assertIn("claimable: no TXT record at asuid.azgone.prov.test", self.one(self.f1, "azgone.prov.test", "FAIL"))
        self.assertIn("deleted-app.azurewebsites.net does NOT resolve", self.f1["azgone.prov.test"][0]["message"])
        # the asuid record names the host, so it only counts for the host it was published for
        self.one(self.f2, "azgone.prov2.test", "FAIL")

    def test_deleted_github_pages_target_is_possibly_claimable(self):
        msg = self.possibly("ghgone", "GitHub Pages", "a TXT record at _github-pages-challenge-<owner>.<domain>")
        self.assertIn("gone-user.github.io does NOT resolve", msg)

    def test_claimed_verifying_provider_stays_ok(self):
        self.assertIn("currently claimed", self.one(self.f1, "ghok.prov.test", "OK"))

    # -- no ownership check in the provider's docs: a flat FAIL \"claimable\"
    def test_providers_without_verification_stay_claimable(self):
        for sub, needle in (("hk", "no such app"), ("sg", "project not found"),
                            ("rd", "the link you have followed"), ("gs", "site unavailable")):
            msg = self.one(self.f1, sub + ".prov.test", "FAIL")
            self.assertIn("claimable: this IS an active subdomain-takeover opportunity", msg)
            self.assertIn(needle, msg)
            self.assertNotIn("possibly", msg)

    def test_s3_bucket_without_ownership_check_stays_claimable(self):
        # AWS: any account can create the bucket a dangling CNAME names (existing fixture bucket.hyg.test)
        out = json.loads(run("hyg.test", "--subdomains", "bucket", "--no-apex-checks", "--json").stdout)
        got = by_name(out, "hyg.test")["bucket.hyg.test"]
        self.assertEqual([x["level"] for x in got], ["FAIL"])
        self.assertIn("claimable cloud service", got[0]["message"])

    def test_exit_code_only_counts_claimable_findings(self):
        # prov2: Vercel INFO + Azure INFO + deleted Azure app FAIL
        self.assertEqual(self.p2.returncode, 1)
        only = run("prov.test", "--subdomains", "gh,nl,pa,vc", "--no-apex-checks")
        self.assertEqual(only.returncode, 0, only.stdout)
        self.assertIn("possibly claimable", only.stdout)
