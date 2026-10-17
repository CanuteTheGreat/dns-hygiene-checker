# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

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
