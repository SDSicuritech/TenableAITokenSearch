# AI Secret Scanner

A Claude Code / AI-assistant skill that scans **authorized, in-scope** web
applications for accidentally exposed AI and cloud API keys in client-delivered
HTML and JavaScript, and produces a masked, remediation-focused report.

Built for defenders: findings are **masked and fingerprinted, never stored in
plaintext**, TLS verification is **on by default**, and scanning is bounded to
an explicit host allowlist.

## What it detects

OpenAI, Anthropic Claude, Google/Gemini, Hugging Face, AWS access key IDs,
Stripe live keys, GitHub tokens, Slack bot tokens, JWTs, and generic
`api_key = "..."` assignments.

## Quick start

```bash
pip install -r requirements.txt
python3 ai_secret_scanner.py --input applications.xlsx --scope scope.txt --output scan_results.xlsx
```

- `applications.xlsx` — a sheet with a column named `URL`.
- `scope.txt` — one authorized host per line (see `scope.txt.example`).

## Authorized use only

This tool is for assessing assets you own or have written permission to test.
It refuses to run without a scope allowlist and skips any target outside it.

See `SKILL.md` for the full skill definition, safety properties, and
limitations. Licensed under MIT.
