"""Offline unit tests for ai_secret_scanner.

These tests use no network. They verify detection, redaction, fingerprint
stability, and scope gating — the properties that make this skill safe to
publish.
"""

import ai_secret_scanner as scanner


def test_detects_common_key_types():
    sample = """
    const cfg = { api_key: "AKIAIOSFODNN7EXAMPLE" };
    var claude = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD";
    let g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
    """
    findings = scanner.scan_text_for_keys(sample, "https://app.example.com", "src.js")
    types = {f["Key Type"] for f in findings}
    assert "AWS Access Key ID" in types
    assert "Anthropic Claude API Key" in types
    assert "Google Gemini / Google API Key" in types


def test_findings_never_contain_full_plaintext_secret():
    secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    findings = scanner.scan_text_for_keys(secret, "https://app.example.com", "src.js")
    assert findings, "expected at least one finding"
    for f in findings:
        assert secret not in f["Masked Value"]
        assert "*" in f["Masked Value"]
        assert f["Masked Value"].endswith(f"(len={len(secret)})")


def test_mask_and_fingerprint():
    s = "AKIAIOSFODNN7EXAMPLE"
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
