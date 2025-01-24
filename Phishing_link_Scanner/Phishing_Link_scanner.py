import re
import requests
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import base64

def load_tlds(file_path):
    """Load TLDs from a file."""
    try:
        with open(file_path, "r") as f:
            tlds = [line.strip() for line in f if line.strip()]
        print(f"TLDs loaded: {len(tlds)} TLDs found.")
        return tlds
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc and "." in parsed.netloc)
    except Exception as e:
        print(f"General error validating URL: {e}")
        return False

def domain_mimic_check(url, trusted_domains):
    parsed = urlparse(url)
    domain = parsed.netloc
    for trusted in trusted_domains:
        if re.search(f"({re.escape(trusted)})$", domain):
            return False
        elif trusted in domain:
            return True
    return False

def check_tld(url, tlds):
    parsed = urlparse(url)
    domain_parts = parsed.netloc.split(".")
    if len(domain_parts) > 1:
        tld = "." + domain_parts[-1]
        if tld not in tlds:
            return f"Uncommon or suspicious TLD detected: {tld}"
    return None

def analyze_url_structure(url):
    parsed_url = urlparse(url)
    decoded_path = unquote(parsed_url.path)
    indicators = []
    if len(parsed_url.netloc.split(".")) > 3:
        indicators.append("Too many subdomains")
    if "/amp/s/" in parsed_url.path:
        indicators.append("Suspicious path structure mimicking trusted domains")
    if "%" in decoded_path:
        indicators.append("Excessive URL encoding detected")
    if re.search(r"[\d]{5,}", parsed_url.path):
        indicators.append("Long numeric sequences in URL path")
    return indicators

def ssl_certificate_check(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return "No HTTPS detected"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return None
        else:
            return f"Non-successful HTTP response code: {response.status_code}"
    except requests.exceptions.SSLError as e:
        return "SSL certificate validation failed"
    except requests.RequestException as e:
        return "Request to the site failed"
    return None

def analyze_page_content(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string if soup.title else ""
        if "login" in title.lower() or "secure" in title.lower():
            return "Suspicious page title detected"
        meta_tags = soup.find_all("meta")
        if any("phishing" in (tag.get("content", "").lower() or "") for tag in meta_tags):
            return "Suspicious meta tag detected"
        return None
    except requests.RequestException as e:
        return "Unable to retrieve page content"

def check_shortened_url(url):
    shortened_services = [
        "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly"
    ]
    parsed = urlparse(url)
    if any(service in parsed.netloc for service in shortened_services):
        return "Shortened URL detected"
    return None

def check_suspicious_query_parameters(url):
    parsed_url = urlparse(url)
    suspicious_patterns = ["redirect", "token", "session", "login", "validate", "id="]
    query_params = unquote(parsed_url.query).lower()
    for pattern in suspicious_patterns:
        if pattern in query_params:
            return f"Suspicious query parameter detected: {pattern}"
    return None

def blacklist_check(url):
    try:
        vt_api_key = "959da0d75d914574cf80d46f368195c53904b3d68bb85d10ef6b800cbc0af34d"
        base64_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{base64_url}"
        response = requests.get(vt_url, headers={"x-apikey": vt_api_key})
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_count > 0:
                return True
    except Exception as e:
        print(f"Error in blacklist check: {e}")
    return False

def phishing_link_scanner(url, trusted_domains_file, tlds_file):
    trusted_domains = load_tlds(trusted_domains_file)
    tlds = load_tlds(tlds_file)
    if not trusted_domains:
        return "Error: Could not load trusted domains"
    if not tlds:
        return "Error: Could not load TLDs"

    if not is_valid_url(url):
        return "Invalid URL"

    findings = []

    if domain_mimic_check(url, trusted_domains):
        findings.append("Domain mimicry detected")

    tld_issue = check_tld(url, tlds)
    if tld_issue:
        findings.append(tld_issue)

    structure_issues = analyze_url_structure(url)
    if structure_issues:
        findings.extend(structure_issues)

    ssl_issue = ssl_certificate_check(url)
    if ssl_issue:
        findings.append(ssl_issue)

    page_issue = analyze_page_content(url)
    if page_issue:
        findings.append(page_issue)

    shortened_url = check_shortened_url(url)
    if shortened_url:
        findings.append(shortened_url)

    suspicious_query = check_suspicious_query_parameters(url)
    if suspicious_query:
        findings.append(suspicious_query)

    if blacklist_check(url):
        findings.append("URL found in a known blacklist")

    if findings:
        return f"Phishing risk detected: {', '.join(findings)}"

    return "The URL is likely safe"

if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    trusted_domains_file = "Domains.txt"  # Path to the trusted domains file
    tlds_file = "TLDs.txt"  # Path to the TLDs file
    print(phishing_link_scanner(test_url, trusted_domains_file, tlds_file))
