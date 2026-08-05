---
name: ai-secret-scanner
description: >
  Scan authorized, in-scope web applications for accidentally exposed AI and
  cloud API keys (OpenAI, Anthropic, Google/Gemini, Hugging Face, AWS, Stripe,
  GitHub, Slack, JWTs) in delivered HTML and linked JavaScript bundles. Use
  when a user wants to check whether their own applications leak secrets to the
  client, triage exposed-credential findings, or produce a remediation report.
  Findings are masked and fingerprinted, never stored in plaintext. Requires an
  explicit in-scope host allowlist; targets outside it are skipped.
license: MIT
category: skills
integrations:
  - Anthropic
  - AWS
tags:
  - secrets-detection
  - api-keys
  - appsec
  - exposure-management
  - vulnerability-assessment
---

# AI Secret Scanner

Detects exposed AI/cloud API credentials in the client-delivered surface of web
applications — the HTML and JavaScript that anyone can retrieve — so defenders
can find and rotate leaked keys before they are abused (e.g., LLMjacking of an
exposed model provider key).

## When to use this skill

Use it when the user asks to:

- Check whether **their own** applications expose API keys in front-end code.
- Batch-scan a list of authorized in-scope URLs and get a remediation report.
- Triage or de-duplicate exposed-credential findings across assets.

## Authorization model (required)

This skill only operates against an **explicit allowlist** the operator
supplies via `--scope`. A target — and every linked JavaScript asset — is
scanned only if its host equals, or is a subdomain of, a listed host.
There is no default/empty scope: with no allowlist the skill refuses to run.
Only scan assets you own or have written permission to test.

## Safety properties

- **Secrets are never written in plaintext.** Every finding is stored as a
  short non-sensitive prefix plus a length-preserving mask
  (`sk-ant******(len=53)`) and a truncated SHA-256 fingerprint for
  cross-asset correlation.
- **TLS verification is ON by default.** The scanner does not silently
  downgrade to HTTP or ignore certificate errors. `--insecure` disables
  verification only when the operator explicitly opts in, with a printed
  warning.
- **Scope-bounded crawling.** Linked JS is followed only when it is itself
  in scope.
- Detections match credential *shapes* and are candidates for manual review,
  not proof of a live key.

## Usage

```bash
pip install pandas openpyxl beautifulsoup4 requests

# scope.txt: one authorized host per line, e.g.
#   app.example.com
#   example.com
# applications.xlsx: a sheet with a column named 'URL'

python3 ai_secret_scanner.py \
  --input applications.xlsx \
  --scope scope.txt \
  --output scan_results.xlsx
```

The report (`scan_results.xlsx`) contains: Application URL, Source Asset, Key
Type, Masked Value, Fingerprint, and a Remediation note. Verify each candidate
against the source asset before rotating.

## Remediation guidance for findings

Any confirmed key in client-delivered code should be treated as compromised:
revoke/rotate it at the provider, remove it from the front-end bundle, and move
the secret server-side behind an authenticated proxy. Add secret scanning to CI
to prevent recurrence.

## Limitations

- Static analysis only; it will not find keys injected at runtime or gated
  behind authentication.
- Shape-based matching can produce false positives (e.g., example keys in docs).
- It does not validate whether a discovered key is active, and intentionally
  provides no capability to do so.
