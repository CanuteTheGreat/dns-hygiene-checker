# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.3.0 - 2026-10-28

- An "unclaimed" page is no longer always reported as claimable. GitHub Pages, Vercel, Netlify, Azure App
  Service and Pantheon let the domain's owner verify the domain, after which other accounts can't attach it,
  so the same page is a real takeover risk on one domain and not on another. Those hosts now get
  WARN `possibly claimable: <provider> blocks takeover if the domain is verified with <mechanism>; check your
  account`. Azure's `asuid.<host>` TXT and Vercel's `_vercel.<domain>` TXT are looked up (found: INFO; Azure
  missing: FAIL). GitHub's TXT name contains the account name, so it can't be checked from DNS. Hosts whose
  docs describe no such check (Heroku, S3, Surge, Read the Docs, Ghost(Pro), ...) stay FAIL, now worded
  "claimable". Thanks to a reader for the correction.
- Tests: one end-to-end test per provider class.

## 1.2.1 - 2026-10-17

- Takeover verdicts follow can-i-take-over-xyz: a dangling CNAME to a service that verifies domain
  ownership before attaching a custom domain (CloudFront, Fastly, Firebase, Fly.io, Statuspage, Zendesk,
  WP Engine, Unbounce, UserVoice, Kinsta, Freshdesk) is a WARN, not a FAIL "takeover"; claimable
  suffixes match on label boundaries (`x.mygithub.io` no longer counts as GitHub Pages).
- Tests: accuracy suite against that list, mutation testing (nightly), claims ledger.

## 1.2.0 - 2026-10-16

- **Subdomain discovery**: `--ct` (Certificate Transparency via crt.sh, Cert Spotter fallback), `--zone-file`
  (BIND zone files / exports) and `--cloudflare` (every record in the Cloudflare zone); `--only-discovered`.
- **Dangling NS delegations** (FAIL when no nameserver resolves), dangling **MX** and **SRV** targets.
- **CAA** and **DNSSEC** checks at the apex (`--no-apex-checks` to skip).
- About 65 claimable hostname patterns (was ~25) and ~30 unclaimed-page fingerprints (was 14).
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/dns-hygiene-checker.git`
  puts a `dns-hygiene-checker` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Report resolver failures instead of a clean result, check A records per address, real wildcard-cert check, SPF multi-string/permerror, --doh-url, add CI tests

## 1.0.0 - 2026-09-16

- First public release.
