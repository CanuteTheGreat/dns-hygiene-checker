#!/usr/bin/env python3
"""
dns-hygiene-checker — find dangling DNS records before someone else finds them for you.

Checks a domain's common subdomains (or a supplied list) for the #1 precondition of
subdomain takeover: a CNAME pointing at a cloud resource (S3 bucket, GitHub Pages,
Heroku, Azure, Fastly, etc.) that has since been deprovisioned or never claimed. Also
flags a few other everyday DNS-hygiene footguns:
  - CNAME target resolves to NXDOMAIN (classic dangling-CNAME takeover setup)
  - CNAME points at a known "claimable" cloud hostname pattern (github.io, s3
    website endpoints, herokuapp.com, azurewebsites.net, fastly.net, etc.) with no
    A/AAAA behind it — these are the ones attackers scan for specifically
  - the same, when the platform answers with its "unclaimed" page. Some platforms let
    the domain owner verify the domain (GitHub Pages, Vercel, Azure App Service, Pantheon),
    after which no other account can attach it. There the finding says "possibly
    claimable ... check your account" instead of "claimable"; it says "claimable"
    only where the provider's docs describe no such protection, or the record that
    would show it (Azure's asuid TXT) is missing
  - A records where some or all addresses no longer answer on port 80/443 (stale infra)
  - SPF "include:" domain that exists but publishes no SPF record (permerror)
  - SPF record referencing an "include:" domain that doesn't resolve
  - Wildcard DNS present without a TLS cert that covers arbitrary subdomains
  - NS delegations whose nameserver hostnames don't resolve (dangling delegation:
    whoever registers that nameserver's domain controls the subdomain)
  - MX and common SRV records pointing at hostnames that don't resolve
  - no CAA record (any CA may issue for the domain), and DNSSEC not enabled

Subdomains to check come from a built-in list of common names and/or
--subdomains, plus discovery: --ct (Certificate Transparency logs via crt.sh,
falling back to Cert Spotter), --zone-file (a BIND zone file / export) and
--cloudflare (every record in the Cloudflare zone, token in
CLOUDFLARE_API_TOKEN).

Uses only the Python standard library (socket, ssl) plus DNS-over-HTTPS via Cloudflare's
free public resolver (https://cloudflare-dns.com/dns-query) — no API key, no signup,
no local `dig`/`host` binary required (this host doesn't have one).

Usage:
    dns-hygiene-checker example.com
    dns-hygiene-checker example.com --subdomains www,mail,staging,old-blog
    dns-hygiene-checker example.com --ct                 # + every name in CT logs
    dns-hygiene-checker example.com --zone-file example.com.zone --only-discovered
    CLOUDFLARE_API_TOKEN=... dns-hygiene-checker example.com --cloudflare
    dns-hygiene-checker example.com --json
    dns-hygiene-checker example.com --doh-url https://dns.google/resolve

Exit codes: 0 = no FAIL findings, 1 = at least one FAIL (takeover risk),
2 = the DNS-over-HTTPS resolver could not be queried (report incomplete).
"""
__version__ = "1.3.0"

import argparse
import json
import os
import socket
import ssl
import sys
import re
import urllib.parse
import urllib.request
import urllib.error

DOH_URL = "https://cloudflare-dns.com/dns-query"
CT_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "CAA": 257}
SRV_NAMES = ["_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_xmpp-client._tcp", "_caldavs._tcp",
             "_carddavs._tcp", "_imaps._tcp", "_submission._tcp"]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "cpanel", "autodiscover", "api", "app", "staging", "dev", "test", "beta",
    "blog", "shop", "store", "docs", "status", "cdn", "static", "assets",
    "old", "legacy", "demo", "vpn", "portal", "admin", "dashboard", "support",
]

# Hostname suffixes of services where a dangling CNAME can be claimed by someone else (rated
# "Vulnerable" or "Edge case" by the community list github.com/EdOverflow/can-i-take-over-xyz):
# if a CNAME points here and the target is gone, an attacker can often just sign up for that
# service and claim the exact hostname to serve content under your domain.
CLAIMABLE_SUFFIXES = [
    ".github.io", ".herokuapp.com", ".herokudns.com", ".s3.amazonaws.com",
    ".s3-website", ".azurewebsites.net", ".azureedge.net", ".cloudapp.net",
    ".netlify.app", ".surge.sh", ".readthedocs.io",
    ".wordpress.com", ".shopify.com", ".myshopify.com",
    ".trafficmanager.net", ".ghost.io",
    ".pantheonsite.io",
    ".elasticbeanstalk.com", ".bitbucket.io", ".helpscoutdocs.com", ".helpjuice.com", ".webflow.io",
    ".tumblr.com", ".cargocollective.com", ".launchrock.com", ".teamwork.com",
    ".strikinglydns.com", ".smartjobboard.com", ".agilecrm.com", ".gitbook.io",
    ".blob.core.windows.net", ".cloudapp.azure.com", ".azure-api.net", ".azurefd.net",
    ".azurecontainer.io", ".azurecr.io", ".azurehdinsight.net", ".redis.cache.windows.net",
    ".servicebus.windows.net", ".search.windows.net", ".vercel.app",
    ".onrender.com", ".pages.dev", ".workers.dev",
    ".ngrok.io", ".frontify.com", ".canny.io", ".simplebooklet.com",
    ".airee.ru", ".animaapp.io", ".trydiscourse.com", ".furyns.com", ".hatenablog.com", ".helprace.com",
    ".youtrack.cloud", ".readme.io", ".surveysparrow.com", ".read.uberflip.com", ".stats.uptimerobot.com",
    ".worksites.net",
]

# Services the same list rates "Not vulnerable": they verify domain ownership, so nobody else can
# claim the hostname. A dangling CNAME to them is still a broken record (WARN), not a takeover.
VERIFIED_SERVICES = {
    ".cloudfront.net": "CloudFront", ".fastly.net": "Fastly", ".firebaseapp.com": "Firebase", ".web.app": "Firebase",
    ".fly.dev": "Fly.io", ".freshdesk.com": "Freshdesk", ".kinsta.cloud": "Kinsta", ".statuspage.io": "Statuspage",
    ".unbouncepages.com": "Unbounce", ".uservoice.com": "UserVoice", ".wpengine.com": "WP Engine",
    ".zendesk.com": "Zendesk", ".elb.amazonaws.com": "AWS ELB", ".squarespace.com": "Squarespace",
    ".hubspot.net": "HubSpot", ".ghs.googlehosted.com": "Google Sites", ".storage.googleapis.com": "Google Cloud Storage",
    ".gitlab.io": "GitLab Pages", ".akamaiedge.net": "Akamai", ".acquia-sites.com": "Acquia",
}


# Hosts that let the domain's owner verify it, after which other accounts can't attach it. Each entry:
# suffix -> (provider, what the owner verifies with, what we can look up in DNS, extra note).
# Sources (the providers' own docs, checked 2026-10-28):
#   GitHub Pages  docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages
#   Vercel        vercel.com/docs/domains/working-with-domains/add-a-domain  ("Verify domain access")
#   Azure         learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain  (domain verification ID)
#   Pantheon      docs.pantheon.io/guides/domains/custom-domains  (verify ownership by DNS TXT or file upload)
# Netlify's public docs describe no ownership TXT, so it is listed as unconfirmed rather than as claimable.
OWNERSHIP_VERIFIED = {
    ".github.io": ("GitHub Pages", "a TXT record at _github-pages-challenge-<owner>.<domain>", None,
                   "The TXT name contains your GitHub user or organization name, so DNS alone can't confirm it."),
    ".vercel.app": ("Vercel", "a TXT record at _vercel.<domain>", "vercel",
                    "Vercel only asks for it when the domain is already in another Vercel account or team."),
    ".netlify.app": ("Netlify", "Netlify's domain ownership checks", None,
                     "Netlify's public docs describe no ownership TXT record, so this is unconfirmed either way."),
    ".azurewebsites.net": ("Azure App Service", "the domain verification ID TXT record at asuid.<host>", "asuid", ""),
    ".pantheonsite.io": ("Pantheon", "an ownership check (a DNS TXT value or a file upload)", None,
                         "Domains added before Pantheon enforced the check are exempt."),
}


def ownership_verdict(fqdn, domain, target, lead):
    """For a CNAME target on a host where the owner can verify the domain: (level, message), else None.
    `lead` is the finding's first half (what we saw at the target)."""
    suffix = suffix_match(target, OWNERSHIP_VERIFIED)
    if suffix is None:
        return None
    provider, mech, probe, note = OWNERSHIP_VERIFIED[suffix]
    if probe == "asuid":
        name = "asuid." + fqdn
        if get_records(name, "TXT")[0]:
            return "INFO", (f"{lead} — {provider}: found a domain verification ID at {name}, so another Azure "
                            "account should not be able to attach this hostname. Still remove the stale CNAME.")
        return "FAIL", (f"{lead} — claimable: no TXT record at {name}, so nothing stops another Azure account "
                        "from adding this hostname to an App Service app (the verification ID is optional). "
                        "Remove the CNAME, or add the asuid TXT record from the app's custom domain page.")
    if probe == "vercel":
        name = "_vercel." + domain
        if get_records(name, "TXT")[0]:
            return "INFO", (f"{lead} — {provider}: found a TXT record at {name}, so the domain looks verified and "
                            "another account should not be able to attach it. Still remove the stale CNAME.")
    return "WARN", (f"{lead} — possibly claimable: {provider} blocks takeover if the domain is verified with "
                    f"{mech}; check your account. {note} Remove the CNAME if nothing is published there.").replace("  ", " ")


def suffix_match(host, suffixes):
    """The suffix (from `suffixes`) `host` falls under, matched on label boundaries, or None.
    ('.s3-website' also matches the regional s3-website-<region>.amazonaws.com forms.)"""
    host = host.lower().rstrip(".")
    for suf in suffixes:
        bare = suf.lstrip(".")
        if host == bare or host.endswith("." + bare):
            return suf
        if suf == ".s3-website" and ".s3-website" in "." + host:
            return suf
    return None


# Fingerprint strings seen in the body of a claimable-but-unclaimed page for
# platforms that resolve generically at the DNS layer but signal "not claimed"
# only in the HTTP response body/status. Checking these turns a DNS-only false
# negative (like Heroku, which resolves fine but 404s with "no such app") into
# a real positive. Only claimable services are listed (see CLAIMABLE_SUFFIXES).
UNCLAIMED_HTTP_SIGNATURES = {
    "herokuapp.com": ("no such app", 404),
    "herokudns.com": ("no such app", 404),
    "github.io": ("there isn't a github pages site here", 404),
    "netlify.app": ("not found - request id", 404),
    "surge.sh": ("project not found", 404),
    "readthedocs.io": ("the link you have followed or the url that you entered does not exist", 404),
    "ghost.io": ("site unavailable", 404),
    "pantheonsite.io": ("404 error unknown site!", 404),
    "azurewebsites.net": ("web app - error 404", 404),
    "trafficmanager.net": ("this domain is not configured", 404),
    "bitbucket.io": ("repository not found", 404),
    "helpscoutdocs.com": ("no settings were found for this company", 404),
    "helpjuice.com": ("we could not find what you're looking for", 404),
    "webflow.io": ("the page you are looking for doesn't exist or has been moved", 404),
    "tumblr.com": ("whatever you were looking for doesn't currently exist at this address", 404),
    "launchrock.com": ("it looks like you may have taken a wrong turn somewhere", 404),
    "teamwork.com": ("oops - we didn't find your site", 404),
    "smartjobboard.com": ("this job board website is either expired or its domain name is invalid", 404),
    "agilecrm.com": ("sorry, this page is no longer available", 404),
    "strikinglydns.com": ("page not found - striking", 404),
    "canny.io": ("there is no such company", 404),
    "vercel.app": ("deployment_not_found", 404),
    "ngrok.io": ("not found", 404),
    "wordpress.com": ("do you want to register", 404),
    "animaapp.io": ("the page you were looking for does not exist", 404),
    "furyns.com": ("404: this page could not be found", 404),
    "hatenablog.com": ("404 blog is not found", 404),
    "youtrack.cloud": ("is not a registered incloud youtrack", 404),
    "readme.io": ("the creators of this project are still working on making everything perfect", 404),
    "surveysparrow.com": ("account not found", 404),
    "read.uberflip.com": ("the url you've accessed does not provide a hub", 404),
    "stats.uptimerobot.com": ("page not found", 404),
    "airee.ru": ("ошибка 402. сервис айри.рф не оплачен", 402),
}


def http_claim_check(host, ips=()):
    """Fetch a claimable-service hostname over HTTPS and look for an
    'unclaimed resource' fingerprint. Returns (is_unclaimed, detail) or
    (None, None) if the check is inconclusive (network error, no match rule)."""
    sig = None
    suffix = suffix_match(host, list(UNCLAIMED_HTTP_SIGNATURES))
    if suffix is not None:
        sig = UNCLAIMED_HTTP_SIGNATURES[suffix]
    if not sig:
        return None, None
    needle, expect_code = sig
    if not ips:
        return None, None
    # Connect to the address the DoH lookup returned (the same view of DNS the
    # rest of this report uses), with SNI + Host set to the platform hostname.
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ips[0], 443), timeout=8)
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dns-hygiene-checker/1.0\r\n"
                        "Accept: text/html\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while len(data) < 16384:
                try:
                    chunk = tls.recv(4096)
                except ssl.SSLError:
                    # Many servers just close without a TLS close_notify; older
                    # Pythons on OpenSSL 3 report that as a generic SSLError.
                    if data:
                        break
                    raise
                if not chunk:
                    break
                data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        code = int(head.split(b" ", 2)[1])
        body = body.decode("utf-8", errors="replace").lower()
    except Exception:
        return None, None
    if needle in body:
        return True, f"HTTP {code} with unclaimed-resource fingerprint (\"{needle}\") on {host}"
    return False, f"HTTP {code}, no unclaimed-resource fingerprint on {host}"




# Resolver lookups that failed outright (network error, non-JSON answer, SERVFAIL).
# A run where the resolver can't be reached must not look like a clean report.
RESOLVER_FAILURES = []


def doh_query(name, rtype, timeout=10):
    url = f"{DOH_URL}?name={urllib.parse.quote(name)}&type={rtype}&do=1"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("resolver answer is not a JSON object")
        return data
    except (urllib.error.URLError, TimeoutError, socket.timeout, ValueError, OSError) as e:
        RESOLVER_FAILURES.append(f"{name}/{rtype}: {e}")
        return None


def get_records(name, rtype):
    data = doh_query(name, rtype)
    if not data:
        return [], None
    status = data.get("Status")
    if status == 2:  # SERVFAIL: the resolver couldn't get an answer, not "no record"
        RESOLVER_FAILURES.append(f"{name}/{rtype}: SERVFAIL")
    answers = data.get("Answer", []) or []
    values = [a["data"] for a in answers if a.get("type") == RTYPES.get(rtype)]
    return values, status


def get_ad(name):
    """(DNSSEC-validated by the resolver?, status) for the name's SOA lookup."""
    data = doh_query(name, "SOA")
    return (bool(data.get("AD")) if data else None), (data or {}).get("Status")


def resolves(host):
    """True if host has an A or AAAA record, False if not (NXDOMAIN or no data)."""
    a, st = get_records(host, "A")
    if a:
        return True
    aaaa, _ = get_records(host, "AAAA")
    return bool(aaaa)


def txt_value(data):
    """Join a TXT record's character-strings: DoH returns '"v=spf1 a" " -all"' for a
    record published as two strings, which DNS consumers concatenate."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


def check_port_open(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_delegation(fqdn, findings):
    """A delegated name (NS records of its own) whose nameserver hostnames don't resolve."""
    ns_vals, _ = get_records(fqdn, "NS")
    dead = []
    for ns in ns_vals:
        host = ns.rstrip(".").lower()
        if not resolves(host):
            dead.append(host)
    if dead and len(dead) == len(ns_vals):
        findings.append((fqdn, "FAIL", f"NS delegation to {', '.join(dead)}, none of which resolve -- a dangling "
                                       "delegation: whoever registers that nameserver domain controls this zone"))
    elif dead:
        findings.append((fqdn, "WARN", f"NS {', '.join(dead)} in the delegation don't resolve (the other "
                                       "nameservers still answer) -- remove them"))
    return bool(ns_vals)


def check_mx(fqdn, findings):
    for mx in get_records(fqdn, "MX")[0]:
        parts = mx.split()
        host = parts[-1].rstrip(".").lower() if parts else ""
        if host and host != "." and not resolves(host):
            findings.append((fqdn, "WARN", f"MX -> {host} does NOT resolve -- mail to this name bounces, and if "
                                           "that domain is unregistered someone could claim it and receive it"))


def check_subdomain(sub, domain, findings):
    fqdn = f"{sub}.{domain}"
    delegated = check_delegation(fqdn, findings)
    cname_vals, cname_status = get_records(fqdn, "CNAME")
    a_vals, a_status = get_records(fqdn, "A")
    if (cname_vals or a_vals) and not delegated:
        check_mx(fqdn, findings)

    if not cname_vals and not a_vals:
        if cname_status == 3 and a_status == 3:  # NXDOMAIN both
            return  # subdomain doesn't exist at all, nothing to report
        return

    if cname_vals:
        target = cname_vals[0].rstrip(".")
        # does the CNAME target itself resolve?
        target_a, target_status = get_records(target, "A")
        target_aaaa, _ = get_records(target, "AAAA")
        is_claimable = suffix_match(target, CLAIMABLE_SUFFIXES) is not None
        verified = VERIFIED_SERVICES.get(suffix_match(target, VERIFIED_SERVICES) or "")

        verdict = None
        if is_claimable and not target_a and not target_aaaa:
            verdict = ownership_verdict(fqdn, domain, target, f"CNAME -> {target} does NOT resolve")
        if verdict:
            findings.append((fqdn, verdict[0], verdict[1]))
        elif not target_a and not target_aaaa:
            level = "FAIL" if is_claimable else "WARN"
            hint = (" — target hostname pattern matches a claimable cloud service; "
                    "this is the classic subdomain-takeover setup, verify and remove/fix ASAP"
                    if is_claimable else
                    f" — {verified} verifies domain ownership, so others can't claim it, but the record is broken"
                    if verified else " — verify this CNAME target is still valid, or remove the record")
            findings.append((fqdn, level, f"CNAME -> {target} does NOT resolve{hint}"))
        elif is_claimable:
            is_unclaimed, detail = http_claim_check(target, target_a)
            verdict = ownership_verdict(fqdn, domain, target, f"CNAME -> {target} resolves at DNS but {detail}") \
                if is_unclaimed else None
            if verdict:
                findings.append((fqdn, verdict[0], verdict[1]))
            elif is_unclaimed:
                findings.append((fqdn, "FAIL", f"CNAME -> {target} resolves at DNS but {detail} "
                                                "— claimable: this IS an active subdomain-takeover opportunity, "
                                                "the cloud platform itself is telling you nobody has "
                                                "claimed this hostname. Remove the CNAME or claim it now."))
            elif is_unclaimed is False:
                findings.append((fqdn, "OK", f"CNAME -> {target} resolves and {detail} "
                                              "(claimable-pattern hostname, but currently claimed)"))
            else:
                findings.append((fqdn, "INFO", f"CNAME -> {target} resolves and points at a claimable "
                                                "cloud service pattern — not currently dangling, but worth "
                                                "noting if that resource is ever decommissioned"))
        else:
            findings.append((fqdn, "OK", f"CNAME -> {target} (resolves fine)"))

    elif a_vals:
        # subdomain has direct A records — check liveness on 80/443
        dead = [ip for ip in a_vals if not (check_port_open(ip, 443) or check_port_open(ip, 80))]
        if not dead:
            findings.append((fqdn, "OK", f"A -> {', '.join(a_vals)} (responsive on 80/443)"))
        elif len(dead) == len(a_vals):
            findings.append((fqdn, "WARN", f"A -> {', '.join(a_vals)} but nothing answers on 80/443 "
                                            "— stale/dead record, low priority but worth pruning"))
        else:
            findings.append((fqdn, "WARN", f"A -> {', '.join(a_vals)}: {', '.join(dead)} does not answer on "
                                            "80/443 while the others do — stale address left in the record "
                                            "set, some visitors will get timeouts"))


def check_spf_includes(domain, findings):
    txt_vals, _ = get_records(domain, "TXT")
    spf = next((v for v in (txt_value(t) for t in txt_vals) if v.lower().startswith("v=spf1")), None)
    if not spf:
        return
    for tok in spf.split():
        if tok.lower().lstrip("+-~?").startswith("include:"):
            inc_domain = tok.split(":", 1)[1].rstrip(".")
            vals, status = get_records(inc_domain, "TXT")
            if status == 3:
                findings.append(("SPF", "WARN",
                                  f"include:{inc_domain} does NOT resolve — dangling SPF include, "
                                  "an abandoned domain here could theoretically be re-registered "
                                  "and used to pass SPF for spoofed mail as if authorized by you"))
            elif status == 0 and not any(txt_value(v).lower().startswith("v=spf1") for v in vals):
                findings.append(("SPF", "WARN",
                                  f"include:{inc_domain} exists but publishes no SPF record — receivers "
                                  "treat this include as a permanent error (SPF permerror)"))


def check_apex(domain, findings):
    check_mx(domain, findings)
    for name in SRV_NAMES:
        for srv in get_records(f"{name}.{domain}", "SRV")[0]:
            parts = srv.split()
            host = parts[-1].rstrip(".").lower() if len(parts) == 4 else ""
            if host and host != "." and not resolves(host):
                findings.append((f"{name}.{domain}", "WARN", f"SRV -> {host} does NOT resolve -- dangling service record"))
    caa = [c for c in get_records(domain, "CAA")[0]]
    if not caa:
        findings.append(("CAA", "WARN", f"no CAA record on {domain}: any certificate authority may issue certificates "
                                        "for it (add e.g. '0 issue \"letsencrypt.org\"' for the CAs you use)"))
    else:
        issuers = [c.split(None, 2)[2].strip('"') for c in caa if len(c.split(None, 2)) == 3 and c.split()[1].lower() == "issue"]
        wild = [c for c in caa if len(c.split()) >= 2 and c.split()[1].lower() == "issuewild"]
        iodef = [c for c in caa if len(c.split()) >= 2 and c.split()[1].lower() == "iodef"]
        findings.append(("CAA", "OK", f"CAA restricts issuance to: {', '.join(issuers) or '(none)'}"
                                      + (f"; issuewild: {len(wild)} record(s)" if wild else "")
                                      + ("" if iodef else " (no iodef: CAs can't report refused requests to you)")))
    ds, _ = get_records(domain, "DS")
    ad, _ = get_ad(domain)
    if not ds:
        findings.append(("DNSSEC", "WARN", f"{domain} is not DNSSEC-signed (no DS record at the parent): answers can be "
                                           "spoofed in transit and DANE/TLSA can't be used"))
    elif ad:
        findings.append(("DNSSEC", "OK", f"{domain} is DNSSEC-signed and the resolver validated it (AD flag)"))
    else:
        findings.append(("DNSSEC", "INFO", f"{domain} has a DS record but the resolver didn't mark answers as "
                                           "validated (non-validating resolver, or a broken chain)"))


def check_wildcard(domain, findings):
    probe = f"dnshygiene-wildcard-probe-{os.getpid()}.{domain}"
    a_vals, status = get_records(probe, "A")
    cname_vals, _ = get_records(probe, "CNAME")
    if not (a_vals or cname_vals):
        return
    if not a_vals and cname_vals:
        a_vals, _ = get_records(cname_vals[0].rstrip("."), "A")
    verdict = wildcard_cert_verdict(probe, a_vals)
    if verdict is True:
        findings.append((domain, "OK", f"Wildcard DNS (*.{domain}) is configured and the TLS certificate "
                                       "served for an arbitrary subdomain covers it"))
    elif verdict is None:
        findings.append((domain, "INFO",
                          "Wildcard DNS (*.{}) appears to be configured — every made-up subdomain "
                          "resolves, but nothing answered TLS on 443 to check the certificate. Make sure "
                          "your TLS cert covers wildcards too, or unexpected subdomains will show cert "
                          "warnings.".format(domain)))
    else:
        findings.append((domain, "WARN",
                          f"Wildcard DNS (*.{domain}) is configured but the TLS certificate served for an "
                          f"arbitrary subdomain does not cover it ({verdict}) — every made-up subdomain "
                          "shows browsers a certificate error"))


def wildcard_cert_verdict(probe, ips):
    """True if the cert served on ips[0]:443 for SNI=probe is valid for probe, None if
    nothing answers TLS there, else a short reason string."""
    if not ips:
        return None
    try:
        raw = socket.create_connection((ips[0], 443), timeout=6)
    except OSError:
        return None
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(raw, server_hostname=probe):
            return True
    except ssl.SSLCertVerificationError as e:
        return getattr(e, "verify_message", None) or str(e)
    except (ssl.SSLError, OSError) as e:
        return f"TLS handshake failed: {e}"
    finally:
        raw.close()


def audit(domain, subdomains, quiet=False, apex_checks=True, notes=()):
    if not quiet:
        print(f"\n=== {domain} ===")
        for n in notes:
            print(f"  [{n[1]:5s}] {n[0]}: {n[2]}")
    findings = []
    for sub in subdomains:
        check_subdomain(sub, domain, findings)
    sub_found = bool(findings)
    check_spf_includes(domain, findings)
    check_wildcard(domain, findings)
    if apex_checks:
        check_apex(domain, findings)

    if not sub_found and not RESOLVER_FAILURES:
        findings.append((domain, "INFO", "no subdomains from the checked list currently resolve — "
                                          "nothing to report (try --subdomains with your real list "
                                          "for a more complete picture)"))

    order = {"FAIL": 0, "WARN": 1, "INFO": 2, "OK": 3}
    findings.sort(key=lambda f: order.get(f[1], 9))
    if not quiet:
        for name, level, msg in findings:
            print(f"  [{level:5s}] {name}: {msg}")
    return findings


def _http_json(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=dict({"User-Agent": "dns-hygiene-checker/%s" % __version__,
                                                    "Accept": "application/json"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def relative_names(names, domain):
    out = set()
    for n in names:
        n = n.strip().lower().rstrip(".")
        if n.startswith("*."):
            n = n[2:]
        if n.endswith("." + domain) and " " not in n:
            out.add(n[: -len(domain) - 1])
    return sorted(out)


def discover_ct(domain):
    """Names from Certificate Transparency: crt.sh first, Cert Spotter if crt.sh fails. Returns (subs, source)."""
    errors = []
    for attempt in range(2):
        try:
            data = _http_json(CT_URL + "?q=" + urllib.parse.quote("%." + domain) + "&output=json", timeout=60)
            names = [v for e in data for v in str(e.get("name_value", "")).split("\n")]
            return relative_names(names, domain), "crt.sh"
        except Exception as e:  # crt.sh is often slow or 5xx
            errors.append("crt.sh: %s" % e)
    try:
        data = _http_json(CERTSPOTTER_URL + "?domain=" + urllib.parse.quote(domain) +
                          "&include_subdomains=true&expand=dns_names", timeout=60)
        return relative_names([n for e in data for n in e.get("dns_names", [])], domain), "Cert Spotter"
    except Exception as e:
        errors.append("Cert Spotter: %s" % e)
    raise RuntimeError("; ".join(errors))


def discover_zone_file(path, domain):
    """Owner names from a BIND-style zone file (also Cloudflare/Route53 exports)."""
    origin, last, names = domain + ".", None, set()
    with open(path) as f:
        for raw in f:
            line = raw.split(";", 1)[0].rstrip()
            if not line.strip():
                continue
            if line.upper().startswith("$ORIGIN"):
                origin = line.split()[1]
                if not origin.endswith("."):
                    origin += "." + domain + "."
                continue
            if line.startswith("$"):
                continue
            if line[0].isspace():
                owner = last
            else:
                owner = line.split()[0]
                if owner == "@":
                    owner = origin
                elif not owner.endswith("."):
                    owner = owner + "." + origin
                last = owner
            if owner:
                names.add(owner)
    return relative_names(names, domain)


def discover_cloudflare(domain):
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        raise RuntimeError("--cloudflare needs CLOUDFLARE_API_TOKEN (a token with Zone:DNS:Read)")
    h = {"Authorization": "Bearer " + token}
    zones = _http_json(CLOUDFLARE_API + "/zones?name=" + urllib.parse.quote(domain), h).get("result") or []
    if not zones:
        raise RuntimeError("no Cloudflare zone named %s visible to this token" % domain)
    names, page = [], 1
    while True:
        d = _http_json("%s/zones/%s/dns_records?per_page=500&page=%d" % (CLOUDFLARE_API, zones[0]["id"], page), h)
        names += [r.get("name", "") for r in d.get("result") or []]
        info = d.get("result_info") or {}
        if page >= int(info.get("total_pages") or 1):
            break
        page += 1
    return relative_names(names, domain)


def main(argv=None):
    global DOH_URL, CT_URL, CERTSPOTTER_URL, CLOUDFLARE_API
    parser = argparse.ArgumentParser(prog="dns-hygiene-checker", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("domains", nargs="+", help="domain(s) to check, e.g. example.com")
    parser.add_argument("--subdomains", help="comma-separated list of subdomains to check "
                                              "instead of the built-in common list")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--doh-url", default=DOH_URL,
                        help="DNS-over-HTTPS JSON endpoint to query (default: %(default)s; "
                             "e.g. https://dns.google/resolve)")
    parser.add_argument("--ct", action="store_true",
                        help="also check every subdomain found in Certificate Transparency logs (crt.sh, Cert Spotter)")
    parser.add_argument("--zone-file", metavar="FILE", help="also check every name in this BIND-style zone file")
    parser.add_argument("--cloudflare", action="store_true",
                        help="also check every record in the domain's Cloudflare zone (CLOUDFLARE_API_TOKEN)")
    parser.add_argument("--only-discovered", action="store_true",
                        help="skip the built-in/--subdomains list; check only discovered names")
    parser.add_argument("--no-apex-checks", action="store_true", help="skip the MX/SRV/CAA/DNSSEC checks")
    parser.add_argument("--ct-url", default=CT_URL, help=argparse.SUPPRESS)
    parser.add_argument("--certspotter-url", default=CERTSPOTTER_URL, help=argparse.SUPPRESS)
    parser.add_argument("--cloudflare-api", default=CLOUDFLARE_API, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    DOH_URL, CT_URL, CERTSPOTTER_URL, CLOUDFLARE_API = args.doh_url, args.ct_url, args.certspotter_url, args.cloudflare_api
    if args.only_discovered and not (args.ct or args.zone_file or args.cloudflare):
        parser.error("--only-discovered needs --ct, --zone-file or --cloudflare")

    base = [] if args.only_discovered else (args.subdomains.split(",") if args.subdomains else COMMON_SUBDOMAINS)
    base = [s.strip() for s in base if s.strip()]

    all_results = {}
    resolver_failed = False
    for domain in args.domains:
        domain = domain.strip().replace("https://", "").replace("http://", "").rstrip("/").lower()
        del RESOLVER_FAILURES[:]
        discovered, notes = [], []
        for flag, fn, label in ((args.ct, discover_ct, "CT"), (args.zone_file, discover_zone_file, "zone file"),
                                (args.cloudflare, discover_cloudflare, "Cloudflare")):
            if not flag:
                continue
            try:
                if fn is discover_ct:
                    found, label = fn(domain)
                elif fn is discover_zone_file:
                    found = fn(args.zone_file, domain)
                else:
                    found = fn(domain)
                discovered += found
                notes.append((domain, "INFO", f"{label}: {len(found)} subdomain name(s) discovered"))
            except (RuntimeError, OSError, ValueError) as e:
                RESOLVER_FAILURES.append(f"{label} discovery: {e}")
        subs = list(dict.fromkeys(base + [d for d in discovered if d]))
        findings = notes + audit(domain, subs, quiet=args.json, apex_checks=not args.no_apex_checks, notes=notes)
        if RESOLVER_FAILURES:
            resolver_failed = True
            msg = (f"{len(RESOLVER_FAILURES)} lookup(s) failed (DNS via {DOH_URL} or discovery), so this "
                   f"report is INCOMPLETE (first: {RESOLVER_FAILURES[0]})")
            findings.insert(0, (domain, "ERROR", msg))
            if not args.json:
                print(f"  [ERROR] {domain}: {msg}")
        all_results[domain] = [{"name": n, "level": l, "message": m} for n, l, m in findings]

    if args.json:
        print(json.dumps(all_results, indent=2))

    has_fail = any(f["level"] == "FAIL" for res in all_results.values() for f in res)
    return 1 if has_fail else (2 if resolver_failed else 0)


if __name__ == "__main__":
    sys.exit(main())
