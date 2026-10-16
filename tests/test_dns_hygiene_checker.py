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
TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15}
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
    ("blog.hyg.test", "CNAME"): ["hyg-blog.example.org."],
    ("hyg-blog.example.org", "A"): [LIVE],
    # SPF published as two character-strings; the includes span both
    ("hyg.test", "TXT"): ['"v=spf1 include:_spf.good.test " "include:gone-mail.test include:nospf.test -all"',
                          '"google-site-verification=abc"'],
    ("_spf.good.test", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 -all"'],
    ("nospf.test", "TXT"): ['"some-other-verification=1"'],
    ("www.clean.test", "A"): [LIVE],
}
EXISTS_EMPTY = {"nospf.test", "clean.test", "hyg.test", "wild.test", "badwild.test", "notls.test"}
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
        body = json.dumps({"Status": status, "Answer": [
            {"name": name + ".", "type": TYPES[rtype], "TTL": 60, "data": d} for d in answers]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PlatformHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host == "unclaimed-app.herokuapp.com":
            code, body = 404, "<html><body>Heroku | No such app</body></html>"
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
    global TMP, CA, CA_KEY, DOH, DOH_URL, HTTPS
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

    DOH = HTTPServer((LIVE, 0), DohHandler)
    DOH_URL = "http://%s:%d/dns-query" % DOH.server_address
    threading.Thread(target=DOH.serve_forever, daemon=True).start()


def tearDownModule():
    DOH.shutdown()
    HTTPS.shutdown()
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


SUBS = "www,dead,mixed,gone,bucket,takeover,claimed,cdn,blog,doesnotexist"


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
        self.assertIn("claimable cloud service pattern", self.one("cdn.hyg.test", "INFO"))

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

    def test_help_lists_options(self):
        p = subprocess.run([sys.executable, TOOL, "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        for opt in ("--subdomains", "--json", "--doh-url"):
            self.assertIn(opt, p.stdout)


if __name__ == "__main__":
    unittest.main()
