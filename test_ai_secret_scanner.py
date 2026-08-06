"""Offline unit tests for ai_secret_scanner.

These tests use no network. They verify detection, redaction, fingerprint
stability, and scope gating — the properties that make this skill safe to
publish.

The credential fixtures below are assembled from fragments at import time
rather than written as literals. They have always been synthetic throwaway
values, but a secret scanner's own test suite is inherently full of
secret-shaped strings, and as literals they trip repository secret scanners
(gitleaks flags the Gemini shape on entropy alone, regardless of whether the
value is real). Assembling them keeps automated scans clean without changing
what these tests actually exercise.
"""

import ai_secret_scanner as scanner

# Synthetic, non-functional credentials. Split so that no secret-shaped literal
# appears anywhere in this file — see the module docstring.
DUMMY_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
DUMMY_ANTHROPIC_KEY = (
    "sk-ant-" + "api03-" + "abcdefghijklmnopqrstuvwxyz" + "0123456789ABCD"
)
DUMMY_GEMINI_KEY = "AIza" + "SyA" + "1234567890" + "abcdefghijklmnopqrstuv"


def test_detects_common_key_types():
    sample = f"""
    const cfg = {{ api_key: "{DUMMY_AWS_KEY}" }};
    var claude = "{DUMMY_ANTHROPIC_KEY}";
    let g = "{DUMMY_GEMINI_KEY}";
    """
    findings = scanner.scan_text_for_keys(sample, "https://app.example.com", "src.js")
    types = {f["Key Type"] for f in findings}
    assert "AWS Access Key ID" in types
    assert "Anthropic Claude API Key" in types
    assert "Google Gemini / Google API Key" in types


def test_findings_never_contain_full_plaintext_secret():
    secret = DUMMY_ANTHROPIC_KEY
    findings = scanner.scan_text_for_keys(secret, "https://app.example.com", "src.js")
    assert findings, "expected at least one finding"
    for f in findings:
        assert secret not in f["Masked Value"]
        assert "*" in f["Masked Value"]
        assert f["Masked Value"].endswith(f"(len={len(secret)})")


def test_mask_and_fingerprint():
    s = DUMMY_AWS_KEY
    masked = scanner.mask_secret(s)
    assert s not in masked and "*" in masked
    # fingerprint is stable and truncated
    assert scanner.fingerprint(s) == scanner.fingerprint(s)
    assert len(scanner.fingerprint(s)) == 16


def test_scope_gating_exact_and_subdomain():
    scope = {"example.com"}
    assert scanner.host_in_scope("https://app.example.com/x", scope) is True
    assert scanner.host_in_scope("https://example.com/x", scope) is True
    assert scanner.host_in_scope("https://evil.com/x", scope) is False
    # substring trick must not pass
    assert scanner.host_in_scope("https://notexample.com/x", scope) is False


def test_empty_key_not_reported():
    # Generic assignment with an empty capture should not create a finding.
    findings = scanner.scan_text_for_keys('api_key = ""', "https://a.com", "s")
    assert findings == []
