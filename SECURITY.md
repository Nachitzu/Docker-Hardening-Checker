# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

If you find a security issue in **Docker Hardening Checker** itself
(analyzer bug, bypass, code execution, etc.), please report it privately:

- **Email:** security@example.com  (replace with your real contact before publishing)
- **Subject prefix:** `[security] docker-hardening-checker`
- **PGP:** (optional) attach a PGP-encrypted message if you prefer

Please do **not** open a public GitHub issue for security bugs.

What to include:

1. Steps to reproduce (a minimal Dockerfile or compose file is best)
2. Expected vs actual behavior
3. The rule id that should have fired (`DF-***` or `DC-***`)
4. The Docker Hardening Checker version (`cli.py --version`)

## What to expect

- **Acknowledgement** within 72 hours.
- **Triage decision** within 7 days: accepted / declined / needs more info.
- **Fix timeline** depends on severity. Critical issues (auth bypass, RCE in
  the analyzer) target a patch within 30 days. Low-severity issues are
  bundled into the next regular release.
- A **CVE** will be requested for confirmed vulnerabilities that meet the
  criteria, and the advisory will be published via GitHub Security Advisories.

## Out of scope

- False positives or false negatives in the rule set — please open a
  regular issue for those.
- Vulnerabilities in third-party libraries (Flask, PyYAML). Report them
  upstream.

## Hall of fame

We will credit reporters (with their permission) in the release notes that
ship the fix.
