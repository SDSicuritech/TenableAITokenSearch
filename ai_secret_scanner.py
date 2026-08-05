#!/usr/bin/env python3
"""
ai_secret_scanner.py — Authorized exposed-credential scanner.

Scans in-scope web applications (HTML + linked JavaScript bundles) for
accidentally exposed AI/cloud API keys and other secrets, and produces a
remediation-focused report. Findings are MASKED and HASHED by default so the
output is safe to store and share — it verifies exposure without becoming a
secondary secrets dump.

INTENDED USE: authorized security assessment of assets you own or have
explicit written permission to test. You must supply an in-scope allowlist;
targets outside it are skipped.
"""

import argparse
import hashlib
import re
import sys
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup

# Detection patterns. These match key SHAPES only; a match is a candidate for
# review, not proof of a valid/active credential.
PATTERNS = {
    "OpenAI API Key": r"sk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,}",
    "Anthropic Claude API Key": r"sk-ant-(?:api\d*-)?[a-zA-Z0-9_-]{32,}",
    "Google Gemini / Google API Key": r"AIzaSy[a-zA-Z0-9_-]{33}",
    "Hugging Face Token": r"hf_[a-zA-Z0-9]{34}",
    "AWS Access Key ID": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    "Stripe Live API Key": r"sk_live_[0-9a-zA-Z]{24,34}",
    "GitHub Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "Slack Bot Token": r"xoxb-[0-9]{10,13}-[a-zA-Z0-9-]+",
    "JSON Web Token (JWT)": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Generic Key Assignment": (
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)"
        r"\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]"
    ),
}

HEADERS = {
    "User-Agent": (
        "ai-secret-scanner/1.0 (authorized security assessment; "
        "https://github.com/YOUR_ORG/ai-secret-scanner)"
    )
}

TIMEOUT = (5, 10)  # (connect, read) seconds


def mask_secret(secret: str) -> str:
    """Return a redacted form that proves a match without leaking the value.

    Keeps a short non-sensitive prefix for triage and replaces the body with a
    length-preserving mask, e.g. 'sk-ant-***(len=51)'.
    """
    prefix = secret[:6]
    return f"{prefix}{'*' * 6}(len={len(secret)})"


def fingerprint(secret: str) -> str:
    """Stable SHA-256 fingerprint so duplicate exposures can be correlated
    across assets without storing the plaintext."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def load_scope(scope_file: str) -> set:
    """Load the authorized in-scope host allowlist (one host per line).

    Lines beginning with '#' and blanks are ignored. Hosts are matched by
    exact hostname or as a parent domain (a target host is in scope if it
    equals, or is a subdomain of, a listed host)."""
    hosts = set()
    with open(scope_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                # Accept bare hosts or full URLs in the scope file.
                parsed = urlparse(line if "//" in line else f"//{line}")
                host = parsed.hostname or line
                hosts.add(host)
    return hosts


def host_in_scope(url: str, scope: set) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    for allowed in scope:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def scan_text_for_keys(text, app_url, source_asset):
    """Match all patterns against text; return masked/fingerprinted findings."""
    findings = []
    for key_type, regex in PATTERNS.items():
        for match in set(re.findall(regex, text)):
            key_value = match[0] if isinstance(match, tuple) else match
            if not key_value:
                continue
            findings.append(
                {
                    "Application URL": app_url,
                    "Source Asset": source_asset,
                    "Key Type": key_type,
                    "Masked Value": mask_secret(key_value),
                    "Fingerprint (SHA-256/16)": fingerprint(key_value),
                    "Remediation": "Revoke/rotate the exposed credential and remove it from client-delivered code.",
                }
            )
    return findings


def get_js_urls(html_content, base_url):
    """Extract linked JavaScript URLs from HTML."""
    soup = BeautifulSoup(html_content, "html.parser")
    js_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_urls.append(urljoin(base_url, src))
    return list(set(js_urls))


def fetch_url(target, verify_tls=True):
    """Fetch a target URL. TLS verification is ON by default.

    Unlike a downgrade-and-ignore approach, this does NOT silently fall back to
    http:// or disable certificate validation. If the caller opts into
    --insecure, verification is disabled explicitly and a warning is emitted."""
    clean_target = target.strip()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = f"https://{clean_target}"

    if not verify_tls:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.get(
            clean_target, headers=HEADERS, timeout=TIMEOUT, verify=verify_tls
        )
        response.raise_for_status()
        return response, response.url
    except requests.exceptions.SSLError as e:
        print(
            f"    [!] TLS verification failed for {clean_target}: {e}\n"
            f"        (Re-run with --insecure ONLY if you understand the risk.)"
        )
    except requests.exceptions.RequestException as e:
        print(f"    [!] Failed to reach {clean_target}: {e}")
    return None, None


def scan_single_app(target_url, scope, verify_tls=True):
    """Scan one in-scope application's HTML and linked JS."""
    if not host_in_scope(target_url, scope):
        print(f"    [-] Skipped (out of authorized scope): {target_url}")
        return []

    findings = []
    response, working_url = fetch_url(target_url, verify_tls=verify_tls)
    if not response:
        return findings

    html = response.text
    findings.extend(scan_text_for_keys(html, working_url, working_url))

    for js_url in get_js_urls(html, working_url):
        if not host_in_scope(js_url, scope):
            continue  # only follow assets within authorized scope
        try:
            js_res = requests.get(
                js_url, headers=HEADERS, timeout=TIMEOUT, verify=verify_tls
            )
            if js_res.status_code == 200:
                findings.extend(scan_text_for_keys(js_res.text, working_url, js_url))
        except requests.exceptions.RequestException:
            continue
    return findings


def process_batch(input_file, output_file, scope_file, verify_tls=True):
    scope = load_scope(scope_file)
    if not scope:
        print(f"[!] Scope file '{scope_file}' is empty. Refusing to scan without an authorized allowlist.")
        return

    try:
        df = pd.read_excel(input_file)
    except Exception as e:
        print(f"[!] Error reading input '{input_file}': {e}")
        return

    if "URL" not in df.columns:
        print("[!] Input must contain a column named 'URL' (case-sensitive).")
        return

    urls = df["URL"].dropna().astype(str).tolist()
    print(f"[*] Loaded {len(urls)} targets; {len(scope)} authorized host(s) in scope.\n")
    if not verify_tls:
        print("[!] TLS verification DISABLED (--insecure). Use only when explicitly justified.\n")

    all_results = []
    for i, url in enumerate(urls, start=1):
        target = url.strip()
        print(f"[{i}/{len(urls)}] {target}")
        results = scan_single_app(target, scope, verify_tls=verify_tls)
        if results:
            print(f"    [+] {len(results)} candidate exposure(s) — masked in report.")
            all_results.extend(results)

    if all_results:
        pd.DataFrame(all_results).to_excel(output_file, index=False)
        print(f"\n[✔] {len(all_results)} candidate finding(s) written (masked) to '{output_file}'.")
        print("[i] Verify each finding manually against the source asset before rotating.")
    else:
        print("\n[-] Scan complete. No candidate exposures identified.")


def main():
    p = argparse.ArgumentParser(
        description="Authorized scanner for exposed AI/cloud API keys in web apps."
    )
    p.add_argument("--input", default="applications.xlsx", help="Excel file with a 'URL' column.")
    p.add_argument("--output", default="scan_results.xlsx", help="Where to write masked findings.")
    p.add_argument("--scope", required=True, help="Authorized in-scope host allowlist (one host per line). REQUIRED.")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Off by default; use only with justification.",
    )
    args = p.parse_args()

    print(
        "This tool is for authorized assessment of assets you own or have written\n"
        "permission to test. Continued use affirms you have that authorization.\n"
    )
    process_batch(args.input, args.output, args.scope, verify_tls=not args.insecure)


if __name__ == "__main__":
    sys.exit(main())
