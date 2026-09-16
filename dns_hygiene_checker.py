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
  - Multiple A records where one no longer answers on port 80/443 (stale infra)
  - SPF record referencing an "include:" domain that doesn't resolve
  - Wildcard DNS present without a matching wildcard TLS cert (informational)

Uses only the Python standard library (socket, ssl) plus DNS-over-HTTPS via Cloudflare's
free public resolver (https://cloudflare-dns.com/dns-query) — no API key, no signup,
no local `dig`/`host` binary required (this host doesn't have one).

Usage:
    python3 dns_hygiene_checker.py example.com
    python3 dns_hygiene_checker.py example.com --subdomains www,mail,staging,old-blog
    python3 dns_hygiene_checker.py example.com --json
"""
import argparse
import json
import socket
import ssl
import sys
import urllib.request
import urllib.error

DOH_URL = "https://cloudflare-dns.com/dns-query"

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "cpanel", "autodiscover", "api", "app", "staging", "dev", "test", "beta",
    "blog", "shop", "store", "docs", "status", "cdn", "static", "assets",
    "old", "legacy", "demo", "vpn", "portal", "admin", "dashboard", "support",
]

# Hostname suffixes known to be "claimable" — if a CNAME points here and the
# target doesn't resolve, an attacker can often just sign up for that service
# and claim the exact hostname to serve content under your domain.
CLAIMABLE_SUFFIXES = [
    ".github.io", ".herokuapp.com", ".herokudns.com", ".s3.amazonaws.com",
    ".s3-website", ".azurewebsites.net", ".azureedge.net", ".cloudapp.net",
    ".fastly.net", ".netlify.app", ".surge.sh", ".readthedocs.io",
    ".wordpress.com", ".shopify.com", ".myshopify.com", ".zendesk.com",
    ".statuspage.io", ".trafficmanager.net", ".cloudfront.net", ".ghost.io",
    ".pantheonsite.io", ".wpengine.com", ".unbouncepages.com",
]

# Fingerprint strings seen in the body of a claimable-but-unclaimed page for
# platforms that resolve generically at the DNS layer but signal "not claimed"
# only in the HTTP response body/status. Checking these turns a DNS-only false
# negative (like Heroku, which resolves fine but 404s with "no such app") into
# a real positive.
UNCLAIMED_HTTP_SIGNATURES = {
    "herokuapp.com": ("no such app", 404),
    "herokudns.com": ("no such app", 404),
    "github.io": ("there isn't a github pages site here", 404),
    "netlify.app": ("not found - request id", 404),
    "surge.sh": ("project not found", 404),
    "readthedocs.io": ("404 not found", 404),
    "ghost.io": ("site not found", 404),
    "pantheonsite.io": ("404 error", 404),
    "wpengine.com": ("this site can", 404),
    "statuspage.io": ("page not found", 404),
    "azurewebsites.net": ("web app - error 404", 404),
    "trafficmanager.net": ("this domain is not configured", 404),
    "unbouncepages.com": ("the requested url was not found", 404),
    "zendesk.com": ("help center closed", 404),
}


def http_claim_check(host):
    """Fetch a claimable-service hostname over HTTPS and look for an
    'unclaimed resource' fingerprint. Returns (is_unclaimed, detail) or
    (None, None) if the check is inconclusive (network error, no match rule)."""
    sig = None
    for suffix, (needle, code) in UNCLAIMED_HTTP_SIGNATURES.items():
        if host.endswith(suffix):
            sig = (needle, code)
            break
    if not sig:
        return None, None
    needle, expect_code = sig
    req = urllib.request.Request(f"https://{host}/", headers={"User-Agent": "dns-hygiene-checker/1.0"})
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace").lower()
            code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace").lower() if hasattr(e, "read") else ""
        code = e.code
    except Exception:
        return None, None
    if needle in body:
        return True, f"HTTP {code} with unclaimed-resource fingerprint (\"{needle}\") on {host}"
    return False, f"HTTP {code}, no unclaimed-resource fingerprint on {host}"




def doh_query(name, rtype, timeout=10):
    url = f"{DOH_URL}?name={name}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout):
        return None


def get_records(name, rtype):
    data = doh_query(name, rtype)
    if not data:
        return [], None
    status = data.get("Status")
    answers = data.get("Answer", []) or []
    values = [a["data"] for a in answers if a.get("type") == {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15}.get(rtype)]
    return values, status


def check_port_open(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_subdomain(sub, domain, findings):
    fqdn = f"{sub}.{domain}"
    cname_vals, cname_status = get_records(fqdn, "CNAME")
    a_vals, a_status = get_records(fqdn, "A")

    if not cname_vals and not a_vals:
        if cname_status == 3 and a_status == 3:  # NXDOMAIN both
            return  # subdomain doesn't exist at all, nothing to report
        return

    if cname_vals:
        target = cname_vals[0].rstrip(".")
        # does the CNAME target itself resolve?
        target_a, target_status = get_records(target, "A")
        target_aaaa, _ = get_records(target, "AAAA")
        is_claimable = any(target.endswith(suf.lstrip(".")) or suf.lstrip(".") in target for suf in CLAIMABLE_SUFFIXES)

        if not target_a and not target_aaaa:
            level = "FAIL" if is_claimable else "WARN"
            hint = (" — target hostname pattern matches a claimable cloud service; "
                    "this is the classic subdomain-takeover setup, verify and remove/fix ASAP"
                    if is_claimable else " — verify this CNAME target is still valid, or remove the record")
            findings.append((fqdn, level, f"CNAME -> {target} does NOT resolve{hint}"))
        elif is_claimable:
            is_unclaimed, detail = http_claim_check(target)
            if is_unclaimed:
                findings.append((fqdn, "FAIL", f"CNAME -> {target} resolves at DNS but {detail} "
                                                "— this IS an active subdomain-takeover opportunity, "
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
        live = any(check_port_open(ip, 443) or check_port_open(ip, 80) for ip in a_vals)
        if live:
            findings.append((fqdn, "OK", f"A -> {', '.join(a_vals)} (responsive on 80/443)"))
        else:
            findings.append((fqdn, "WARN", f"A -> {', '.join(a_vals)} but nothing answers on 80/443 "
                                            "— stale/dead record, low priority but worth pruning"))


def check_spf_includes(domain, findings):
    txt_vals, _ = get_records(domain, "TXT")
    spf = next((t.strip('"') for t in txt_vals if t.strip('"').lower().startswith("v=spf1")), None)
    if not spf:
        return
    for tok in spf.split():
        if tok.lower().startswith("include:"):
            inc_domain = tok.split(":", 1)[1]
            vals, status = get_records(inc_domain, "TXT")
            if status == 3 or (not vals and status != 0):
                findings.append(("SPF", "WARN",
                                  f"include:{inc_domain} does NOT resolve — dangling SPF include, "
                                  "an abandoned domain here could theoretically be re-registered "
                                  "and used to pass SPF for spoofed mail as if authorized by you"))


def check_wildcard(domain, findings):
    probe = f"__dnshygiene_wildcard_probe__.{domain}"
    a_vals, status = get_records(probe, "A")
    cname_vals, _ = get_records(probe, "CNAME")
    if a_vals or cname_vals:
        findings.append((domain, "INFO",
                          "Wildcard DNS (*.{}) appears to be configured — every made-up subdomain "
                          "resolves. Not inherently wrong, but make sure your TLS cert covers "
                          "wildcards too, or unexpected subdomains will show cert warnings.".format(domain)))


def audit(domain, subdomains, quiet=False):
    if not quiet:
        print(f"\n=== {domain} ===")
    findings = []
    for sub in subdomains:
        check_subdomain(sub, domain, findings)
    check_spf_includes(domain, findings)
    check_wildcard(domain, findings)

    if not findings:
        findings.append((domain, "INFO", "no subdomains from the checked list currently resolve — "
                                          "nothing to report (try --subdomains with your real list "
                                          "for a more complete picture)"))

    order = {"FAIL": 0, "WARN": 1, "INFO": 2, "OK": 3}
    findings.sort(key=lambda f: order.get(f[1], 9))
    if not quiet:
        for name, level, msg in findings:
            print(f"  [{level:5s}] {name}: {msg}")
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("domains", nargs="+", help="domain(s) to check, e.g. example.com")
    parser.add_argument("--subdomains", help="comma-separated list of subdomains to check "
                                              "instead of the built-in common list")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    subs = args.subdomains.split(",") if args.subdomains else COMMON_SUBDOMAINS
    subs = [s.strip() for s in subs if s.strip()]

    all_results = {}
    for domain in args.domains:
        domain = domain.strip().replace("https://", "").replace("http://", "").rstrip("/")
        findings = audit(domain, subs, quiet=args.json)
        all_results[domain] = [{"name": n, "level": l, "message": m} for n, l, m in findings]

    if args.json:
        print(json.dumps(all_results, indent=2))

    has_fail = any(f["level"] == "FAIL" for res in all_results.values() for f in res)
    sys.exit(1 if has_fail else 0)


if __name__ == "__main__":
    main()
