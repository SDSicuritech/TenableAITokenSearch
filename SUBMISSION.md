# Submission materials — AI Secret Scanner

Use these when opening the pull request to the CyberAgents Exchange (or when
the `/cyberagents-exchange-submit` skill prompts you). Paste the blurb where a
short listing description is requested and the PR body where the pull request
template asks for details.

---

## Listing blurb (short — for the Exchange card)

**AI Secret Scanner** — Scans authorized, in-scope web applications for exposed
AI and cloud API keys (OpenAI, Anthropic, Google/Gemini, Hugging Face, AWS,
Stripe, GitHub, Slack, JWT) in client-delivered HTML and JavaScript. Findings
are masked and fingerprinted — never stored in plaintext — TLS verification is
on by default, and scanning is bounded to an explicit host allowlist. Produces
a remediation-focused report so defenders can rotate leaked keys before they're
abused (e.g., LLMjacking of an exposed provider key).

- **Type:** Skill
- **License:** MIT
- **Integrations:** Anthropic, AWS
- **Tags:** secrets-detection, api-keys, appsec, exposure-management, vulnerability-assessment

---

## Pull request title

Add skill: AI Secret Scanner (exposed AI/cloud API key detection)

---

## Pull request body

### What this is
A skill that scans the client-delivered surface of web applications — the HTML
and linked JavaScript anyone can retrieve — for accidentally exposed AI and
cloud API credentials, and produces a masked, remediation-focused report.

### Why it's useful
Front-end code routinely leaks provider keys. An exposed OpenAI or Anthropic
key can be abused for LLMjacking (running up cost/quota on the victim's
account); an exposed AWS key ID is a foothold. This skill lets defenders find
those exposures across a portfolio of their own assets and rotate them fast.

### Safety / responsible-use properties
This is a dual-use capability, so the skill is deliberately built to be
defensive:

- **No plaintext secrets in output.** Every finding is stored as a short
  non-sensitive prefix + length-preserving mask (`sk-ant******(len=53)`) plus a
  truncated SHA-256 fingerprint for cross-asset correlation.
- **TLS verification on by default.** No silent HTTP downgrade, no ignored
  certificate errors. `--insecure` is an explicit opt-in with a printed
  warning.
- **Scope-gated.** Requires an explicit `--scope` host allowlist; refuses to
  run without one and skips any target (and any linked JS) outside it.
- **Detection, not exploitation.** Matches credential shapes as candidates for
  manual review; provides no capability to validate whether a key is live.

### Testing
Offline pytest suite (`test_ai_secret_scanner.py`) covering detection,
redaction, fingerprint stability, and scope gating. GitHub Actions CI runs it
on Python 3.10–3.12. No network access required to test.

### Repo contents
- `SKILL.md` — skill definition + frontmatter
- `ai_secret_scanner.py` — the scanner
- `test_ai_secret_scanner.py` — offline tests
- `.github/workflows/ci.yml` — CI
- `README.md`, `requirements.txt`, `scope.txt.example`, `LICENSE`

### Authorization
For assessing assets the operator owns or has written permission to test. The
scope allowlist and authorization notice enforce and communicate this.

---

## Before you submit — checklist

- [ ] Push these files to a **public** GitHub repo.
- [x] Repo path set to `SDSicuritech/TenableAITokenSearch` in the User-Agent.
- [ ] Confirm CI is green on the repo (Actions tab).
- [ ] Confirm the `LICENSE` copyright line names you correctly.
- [ ] From the repo directory in Claude Code, run `/cyberagents-exchange-submit`
      (or open a manual PR per the Contributing guide).
