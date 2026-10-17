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

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/dns-hygiene-checker.git        # latest release branch; puts `dns-hygiene-checker` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/dns-hygiene-checker.git@v1.2.1  # a pinned release
brew install canutethegreat/errant-tools/dns-hygiene-checker   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/dns-hygiene-checker                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.7+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/dns_hygiene_checker.py && python3 dns_hygiene_checker.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/dns-hygiene-checker/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install dns-hygiene-checker` doesn't work until it's published there.

## Usage

```
dns-hygiene-checker example.com
dns-hygiene-checker example.com --subdomains www,mail,staging,old-blog
dns-hygiene-checker example.com --ct                        # + every name seen in Certificate Transparency
dns-hygiene-checker example.com --zone-file example.com.zone # + every name in a BIND zone file / export
CLOUDFLARE_API_TOKEN=... dns-hygiene-checker example.com --cloudflare --only-discovered
dns-hygiene-checker example.com --json
dns-hygiene-checker example.com --doh-url https://dns.google/resolve
```

**Which names get checked:** the built-in list of ~33 common names (or `--subdomains`),
plus anything discovered: `--ct` reads Certificate Transparency logs through crt.sh and
falls back to Cert Spotter when crt.sh is down; `--zone-file` reads owner names from a
zone file; `--cloudflare` lists every record in the domain's Cloudflare zone (token with
Zone:DNS:Read in `CLOUDFLARE_API_TOKEN`). `--only-discovered` drops the built-in list.

`--doh-url` picks any DNS-over-HTTPS endpoint that speaks the JSON API (default:
Cloudflare's). Exit codes: `0` no FAIL findings, `1` at least one FAIL (takeover
risk), `2` the resolver or a discovery source couldn't be queried, so the report is
incomplete. Python 3.7+.

What it flags:
- CNAME whose target doesn't resolve (WARN; FAIL when the target is one of 60 claimable
  cloud hostname patterns (services rated takeover-able by
  [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz); ones that verify
  domain ownership, e.g. CloudFront or Fastly, stay WARN)), or that resolves to a platform page saying the hostname is
  unclaimed (FAIL; ~30 HTTP fingerprints)
- **NS delegations** whose nameserver hostnames don't resolve (FAIL when none do: whoever
  registers that nameserver's domain controls the subdomain)
- **MX** (apex and every checked name) and common **SRV** records pointing at names that
  don't resolve (WARN)
- A records where some or all addresses no longer answer on 80/443 (WARN)
- SPF `include:` domains that don't exist, or exist without an SPF record (WARN)
- wildcard DNS: checks the TLS certificate actually served for a made-up subdomain
  (OK if it covers it, WARN if browsers would get a certificate error)
- **CAA**: none at the apex means any CA may issue certificates for the domain (WARN)
- **DNSSEC**: no DS record at the parent (WARN); signed and validated (OK)

`--no-apex-checks` skips the MX/SRV/CAA/DNSSEC checks.

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
