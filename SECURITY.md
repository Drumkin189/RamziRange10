# Security Policy

## This project is intentionally vulnerable

RamziRange10 is a deliberately insecure web application built as a target for
authorized penetration testing and security training. **Every vulnerability in
this repository is present on purpose.**

Please do **not** open security reports for the vulnerabilities it ships —
SQL injection, command injection, path traversal, XXE, SSRF, XSS, template
injection, exposed credentials and the rest are the entire point of the
project.

## Credentials in this repository are fake

All API keys, tokens and private keys are non-functional:

- The AWS secret access key is Amazon's own published example string.
- Every other value carries `RR10`, `Fake`, `EXAMPLE` or `NotReal` markers.
- Webhook, registry and database hostnames use reserved `.test` domains or
  non-routable `.internal` names.
- Only the key *prefixes* are real (`AKIA`, `ghp_`, `github_pat_`, `glpat-`,
  `dckr_pat_`, `xoxb-`, `sk_live_`, `SG.`, `npm_`, `AIza`), which is what makes
  them detectable by scanners without authenticating anywhere.

There is a whole wing of the application — `/vault/*` — whose only job is to
serve credential-shaped strings. That is deliberate; see the README section on
the split surface for why.

Automated secret scanning will flag this repository. That is expected. Allow
the detections, or keep the repository private.

## No real infrastructure is referenced

Unlike an earlier range in this series, RamziRange10 was sanitized from the
first commit. It contains no real operating-system accounts, no real LAN
addresses, and no credential that authenticates against anything. The
lateral-movement account it advertises (`svc_deploy` / `D3pl0y!R3l3ase2026` at
`10.30.0.5`) is fictional.

## What IS worth reporting

- A vulnerability in the *deployment* that could affect a host outside the
  container boundary in a way not already documented.
- A real, working credential that has accidentally been committed.

Open an issue for either.

## Safe deployment

- Isolated lab network only. Never internet-facing.
- Treat the container as compromised by design (`/admin/exec` runs as root).
- Tear it down when you are finished: `docker compose down -v`
