"""Accuracy of the takeover classification against the reference list everyone uses:
github.com/EdOverflow/can-i-take-over-xyz (README table, snapshot 2026-10-16).

* every service the list rates "Vulnerable" or "Edge case" that names a hostname suffix must be
  classified claimable (a dangling CNAME to it is FAIL) -> false-negative suite;
* every service it rates "Not vulnerable" (they verify domain ownership) must NOT be claimable
  (dangling = WARN, with the service named) -> false-positive suite;
* suffixes match on DNS label boundaries only (look-alike registrable domains are not the service).

The end-to-end behaviour (FAIL/WARN/INFO/OK per CNAME) is covered by test_dns_hygiene_checker.py;
this file pins the data the tool decides with.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dns_hygiene_checker as dhc  # noqa: E402

# can-i-take-over-xyz "Vulnerable" / "Edge case" rows, one realistic CNAME target per suffix
VULNERABLE = {
    "AWS/Elastic Beanstalk": "myapp.us-east-1.elasticbeanstalk.com",
    "AWS/S3": "assets.s3.amazonaws.com",
    "AWS/S3 website": "assets.s3-website-us-east-1.amazonaws.com",
    "Agile CRM": "acme.agilecrm.com",
    "Airee.ru": "acme.airee.ru",
    "Anima": "acme.animaapp.io",
    "Bitbucket": "acme.bitbucket.io",
    "Canny": "acme.canny.io",
    "Cargo Collective": "acme.cargocollective.com",
    "Discourse": "acme.trydiscourse.com",
    "Frontify": "acme.frontify.com",
    "Gemfury": "acme.furyns.com",
    "Ghost": "acme.ghost.io",
    "Github": "acme.github.io",
    "HatenaBlog": "acme.hatenablog.com",
    "Help Juice": "acme.helpjuice.com",
    "Help Scout": "acme.helpscoutdocs.com",
    "Helprace": "acme.helprace.com",
    "Heroku": "acme-app.herokuapp.com",
    "Heroku DNS": "acme.herokudns.com",
    "JetBrains": "acme.youtrack.cloud",
    "LaunchRock": "acme.launchrock.com",
    "Azure cloudapp.net": "acme.cloudapp.net",
    "Azure cloudapp.azure.com": "acme.eastus.cloudapp.azure.com",
    "Azure websites": "acme.azurewebsites.net",
    "Azure blob": "acme.blob.core.windows.net",
    "Azure API": "acme.azure-api.net",
    "Azure HDInsight": "acme.azurehdinsight.net",
    "Azure CDN": "acme.azureedge.net",
    "Azure container": "acme.eastus.azurecontainer.io",
    "Azure redis": "acme.redis.cache.windows.net",
    "Azure Front Door": "acme.azurefd.net",
    "Azure service bus": "acme.servicebus.windows.net",
    "Azure search": "acme.search.windows.net",
    "Azure traffic manager": "acme.trafficmanager.net",
    "Azure container registry": "acme.azurecr.io",
    "Netlify": "acme.netlify.app",
    "Ngrok": "acme.ngrok.io",
    "Pantheon": "live-acme.pantheonsite.io",
    "Readme.io": "acme.readme.io",
    "Readthedocs": "acme.readthedocs.io",
    "Shopify": "acme.myshopify.com",
    "SmartJobBoard": "acme.smartjobboard.com",
    "Strikingly": "s.strikinglydns.com",
    "Surge.sh": "na-west1.surge.sh",
    "SurveySparrow": "acme.surveysparrow.com",
    "Tumblr": "domains.tumblr.com",
    "Uberflip": "acme.read.uberflip.com",
    "Uptimerobot": "stats.uptimerobot.com",
    "Vercel": "acme.vercel.app",
    "Webflow": "proxy-ssl.webflow.io",
    "Wordpress": "acme.wordpress.com",
    "Worksites": "acme.worksites.net",
}

# "Not vulnerable" rows: the platform verifies ownership, nobody else can claim the name
NOT_VULNERABLE = {
    "CloudFront": "d111111abcdef8.cloudfront.net",
    "AWS ELB": "acme-123.us-east-1.elb.amazonaws.com",
    "Fastly": "acme.global.ssl.fastly.net",
    "Firebase": "acme.firebaseapp.com",
    "Fly.io": "acme.fly.dev",
    "Freshdesk": "acme.freshdesk.com",
    "Gitlab": "acme.gitlab.io",
    "Google Cloud Storage": "acme.storage.googleapis.com",
    "HubSpot": "acme.hubspot.net",
    "Kinsta": "acme.kinsta.cloud",
    "Squarespace": "ext-cust.squarespace.com",
    "Statuspage": "acme.statuspage.io",
    "Unbounce": "acme.unbouncepages.com",
    "UserVoice": "acme.uservoice.com",
    "WP Engine": "acme.wpengine.com",
    "Zendesk": "acme.zendesk.com",
}

LOOKALIKES = ["pages.notgithub.io", "github.io.attacker.example", "mys3.amazonaws.com.evil.example",
              "fakeherokuapp.com", "x.notazurewebsites.net", "cloudfront.net.example.org"]


class TestAgainstCanITakeOverXyz(unittest.TestCase):
    def test_vulnerable_services_are_claimable(self):
        missed = sorted(name for name, host in VULNERABLE.items()
                        if dhc.suffix_match(host, dhc.CLAIMABLE_SUFFIXES) is None)
        self.assertEqual(missed, [], "takeover-able services the tool would only WARN about")

    def test_not_vulnerable_services_are_not_claimable_and_are_named(self):
        wrong = sorted(name for name, host in NOT_VULNERABLE.items()
                       if dhc.suffix_match(host, dhc.CLAIMABLE_SUFFIXES) is not None)
        self.assertEqual(wrong, [], "ownership-verifying services the tool would call a takeover")
        unnamed = sorted(name for name, host in NOT_VULNERABLE.items()
                         if dhc.suffix_match(host, dhc.VERIFIED_SERVICES) is None)
        self.assertEqual(unnamed, [])

    def test_lists_are_disjoint_and_counted(self):
        self.assertEqual(set(dhc.CLAIMABLE_SUFFIXES) & set(dhc.VERIFIED_SERVICES), set())
        self.assertEqual(len(dhc.CLAIMABLE_SUFFIXES), len(set(dhc.CLAIMABLE_SUFFIXES)), "duplicate suffix")
        # the README states the number
        with open(os.path.join(os.path.dirname(dhc.__file__), "README.md")) as f:
            self.assertIn("one of %d claimable" % len(dhc.CLAIMABLE_SUFFIXES), " ".join(f.read().split()))

    def test_label_boundaries(self):
        for host in LOOKALIKES:
            self.assertIsNone(dhc.suffix_match(host, dhc.CLAIMABLE_SUFFIXES), host)
            self.assertIsNone(dhc.suffix_match(host, dhc.VERIFIED_SERVICES), host)
        self.assertEqual(dhc.suffix_match("GitHub.IO.", dhc.CLAIMABLE_SUFFIXES), ".github.io")
        self.assertEqual(dhc.suffix_match("acme.GITHUB.io.", dhc.CLAIMABLE_SUFFIXES), ".github.io")

    def test_every_http_fingerprint_belongs_to_a_claimable_service(self):
        stray = sorted(s for s in dhc.UNCLAIMED_HTTP_SIGNATURES
                       if dhc.suffix_match("x." + s, dhc.CLAIMABLE_SUFFIXES) is None)
        self.assertEqual(stray, [])

    def test_ownership_verified_hosts_are_claimable_with_fingerprints(self):
        # a host in OWNERSHIP_VERIFIED only changes the verdict of an "unclaimed" answer, so it must be one
        for suffix in dhc.OWNERSHIP_VERIFIED:
            self.assertEqual(dhc.suffix_match("x" + suffix, dhc.CLAIMABLE_SUFFIXES), suffix)
            self.assertIsNotNone(dhc.suffix_match("x" + suffix, list(dhc.UNCLAIMED_HTTP_SIGNATURES)), suffix)


if __name__ == "__main__":
    unittest.main()
