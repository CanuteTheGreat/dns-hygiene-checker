# dns-hygiene-checker

Find dangling DNS records before an attacker does. Checks common subdomains for the
classic subdomain-takeover precondition (a CNAME pointing at a deprovisioned/unclaimed
cloud resource — S3, GitHub Pages, Heroku, Azure, Netlify, Fastly, etc.), plus a few
other everyday DNS-hygiene issues: stale A records that no longer answer, dangling SPF
`include:` domains, and wildcard DNS without a certificate that covers it.

Goes beyond a DNS-only check: for claimable-service hostnames that *do* resolve at the
DNS layer (many do, generically), it also does an HTTP-layer fingerprint check, because
platforms like Heroku and GitHub Pages resolve fine but return a distinctive "no such
app" / "there isn't a GitHub Pages site here" page when the hostname isn't actually
claimed — which is the real, currently-exploitable signal.

Zero dependencies beyond the Python standard library. Uses Cloudflare's free
DNS-over-HTTPS resolver (no local `dig`/`host` binary needed, no API key, no signup).

## Usage

```
python3 dns_hygiene_checker.py example.com
python3 dns_hygiene_checker.py example.com --subdomains www,mail,staging,old-blog
python3 dns_hygiene_checker.py example.com --json
python3 dns_hygiene_checker.py example.com --doh-url https://dns.google/resolve
```

`--doh-url` picks any DNS-over-HTTPS endpoint that speaks the JSON API (default:
Cloudflare's). Exit codes: `0` no FAIL findings, `1` at least one FAIL (takeover
risk), `2` the resolver couldn't be queried, so the report is incomplete. Python 3.7+.

What it flags, per record type:
- CNAME whose target doesn't resolve (WARN; FAIL when the target is a claimable cloud
  hostname), or that resolves to a platform page saying the hostname is unclaimed (FAIL)
- A records where some or all addresses no longer answer on 80/443 (WARN)
- SPF `include:` domains that don't exist, or exist without an SPF record (WARN)
- wildcard DNS: checks the TLS certificate actually served for a made-up subdomain
  (OK if it covers it, WARN if browsers would get a certificate error)

## Example output

```
=== example.com ===
  [FAIL ] forgotten.example.com: CNAME -> forgotten-app.herokuapp.com resolves at DNS but
          HTTP 404 with unclaimed-resource fingerprint ("no such app") on
          forgotten-app.herokuapp.com — this IS an active subdomain-takeover opportunity,
          the cloud platform itself is telling you nobody has claimed this hostname.
          Remove the CNAME or claim it now.
  [OK   ] www.example.com: A -> 93.184.216.34 (responsive on 80/443)
```

Part of the Errant Solutions free/pay-what-you-want toolset — see
https://errant.solutions for the rest (sshd-hardening-auditor, tls-cert-watchdog,
mail-security-auditor, aws-waste-finder, docker-baseline-auditor,
nginx-config-auditor, cert-transparency-watcher, security-txt-auditor).

Pay what you want (including $0) if it's useful: https://errant.solutions

## License

MIT — see LICENSE.
