import re
from urllib.parse import urljoin
import pandas as pd
import requests
import urllib3
from bs4 import BeautifulSoup

# Disable SSL/TLS warnings in console
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded Regular Expressions including AI and Cloud API Keys
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
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]"
    ),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# (Connect Timeout = 5s, Read Timeout = 10s)
TIMEOUT = (5, 10)


def scan_text_for_keys(text, app_url, source_asset):
    """Scans text content against all defined regex patterns."""
    findings = []
    for key_type, regex in PATTERNS.items():
        matches = re.findall(regex, text)
        for match in set(matches):
            key_value = match[0] if isinstance(match, tuple) else match
            findings.append(
                {
                    "Application URL": app_url,
                    "Source Asset": source_asset,
                    "Key Type": key_type,
                    "Discovered Key": key_value,
                }
            )
    return findings


def get_js_urls(html_content, base_url):
    """Extracts all linked JavaScript URLs from HTML."""
    soup = BeautifulSoup(html_content, "html.parser")
    js_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_urls.append(urljoin(base_url, src))
    return list(set(js_urls))


def fetch_url(target):
    """Attempts to fetch target content cleanly.

    Tries original URL, and if it fails or times out, falls back to HTTP or
    HTTPS.
    """
    clean_target = target.strip()

    # Determine trial URLs
    if clean_target.startswith("https://"):
        urls_to_try = [clean_target, clean_target.replace("https://", "http://", 1)]
    elif clean_target.startswith("http://"):
        urls_to_try = [clean_target, clean_target.replace("http://", "https://", 1)]
    else:
        # Default try HTTP first for IPs/Domains without explicit scheme, then HTTPS
        urls_to_try = [f"http://{clean_target}", f"https://{clean_target}"]

    last_error = None
    for url in urls_to_try:
        try:
            response = requests.get(
                url, headers=HEADERS, timeout=TIMEOUT, verify=False
            )
            response.raise_for_status()
            return response, url
        except requests.exceptions.RequestException as e:
            last_error = e
            continue  # Try next protocol scheme

    print(f"    [!] Failed to reach {clean_target} (Tried both HTTP/HTTPS): {last_error}")
    return None, None


def scan_single_app(target_url):
    """Scans HTML and linked JS bundles for a single application."""
    app_findings = []

    # 1. Fetch main HTML with protocol fallback & SSL bypass
    response, working_url = fetch_url(target_url)
    if not response:
        return app_findings

    html_content = response.text
    app_findings.extend(
        scan_text_for_keys(html_content, working_url, working_url)
    )

    # 2. Fetch linked JS files
    js_urls = get_js_urls(html_content, working_url)
    for js_url in js_urls:
        try:
            js_res = requests.get(
                js_url, headers=HEADERS, timeout=TIMEOUT, verify=False
            )
            if js_res.status_code == 200:
                app_findings.extend(
                    scan_text_for_keys(js_res.text, working_url, js_url)
                )
        except Exception:
            continue

    return app_findings


def process_excel_batch(
    input_file="applications.xlsx", output_file="scan_results.xlsx"
):
    """Reads URLs/IPs from Excel, runs scans, and outputs an aggregated report."""
    try:
        df = pd.read_excel(input_file)
    except Exception as e:
        print(f"[!] Error reading Excel file '{input_file}': {e}")
        return

    if "URL" not in df.columns:
        print(
            "[!] Excel file must contain a column named 'URL' (case-sensitive)."
        )
        return

    urls = df["URL"].dropna().astype(str).tolist()
    print(f"[*] Loaded {len(urls)} target entries from {input_file}.\n")

    all_results = []

    for index, url in enumerate(urls, start=1):
        target = url.strip()
        print(f"[{index}/{len(urls)}] Scanning target: {target}")

        findings = scan_single_app(target)
        if findings:
            print(f"    [+] Found {len(findings)} potential key(s)!")
            all_results.extend(findings)

    # Export findings to Excel
    if all_results:
        results_df = pd.DataFrame(all_results)
        results_df.to_excel(output_file, index=False)
        print(
            f"\n[✔] Scan complete! Identified {len(all_results)} total key occurrences."
        )
        print(f"[✔] Results exported to '{output_file}'")
    else:
        print("\n[-] Scan complete. No keys or secret signatures identified.")


if __name__ == "__main__":
    process_excel_batch("applications.xlsx", "scan_results.xlsx")