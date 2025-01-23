import re
import requests
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import ssl
import base64


def is_valid_url(url):
    """Check if the given URL is valid."""
    try:
        parsed = urlparse(url)
        print(f"URL parsed: {parsed}")
        return bool(parsed.scheme and parsed.netloc and "." in parsed.netloc)
    except Exception as e:
        print(f"General error validating URL: {e}")
        return False


def load_trusted_domains(file_path):
    """Load trusted domains from a file."""
    try:
        with open(file_path, "r") as f:
            trusted_domains = [line.strip() for line in f if line.strip()]
        print(f"Trusted domains loaded: {trusted_domains}")
        return trusted_domains
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []


def domain_mimic_check(url, trusted_domains):
    """Check if the domain is mimicking a trusted domain."""
    parsed = urlparse(url)
    domain = parsed.netloc
    print(f"Checking domain mimicry for: {domain}")

    for trusted in trusted_domains:
        if re.search(f"({re.escape(trusted)})$", domain):
            print(f"Trusted domain found: {trusted}")
            return False
        elif trusted in domain:
            print(f"Domain mimicry detected: {domain} contains {trusted}")
            return True
    return False


def check_uncommon_tld(url):
    """Check if the URL uses an uncommon TLD, which could be suspicious."""
    parsed = urlparse(url)
    common_tlds = [".com", ".org", ".net", ".gov", ".edu", ".co", ".us", ".uk", ".eu"]

    domain_parts = parsed.netloc.split(".")
    if len(domain_parts) > 1:
        tld = "." + domain_parts[-1]
        print(f"TLD detected: {tld}")
        if tld not in common_tlds:
            return f"Uncommon TLD detected: {tld}"
    return None


def analyze_url_structure(url):
    """Analyze the structure of the URL for phishing indicators."""
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

    print(f"URL structure issues: {indicators}")
    return indicators


def ssl_certificate_check(url):
    """Check the SSL certificate using requests' built-in verification."""
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            print("No HTTPS detected")
            return "No HTTPS detected"

        print(f"Checking SSL for: {url}")
        response = requests.get(url, timeout=5)
        print(f"SSL check response code: {response.status_code}")

        if response.status_code == 200:
            return None
        else:
            return f"Non-successful HTTP response code: {response.status_code}"

    except requests.exceptions.SSLError as e:
        print(f"SSL error: {e}")
        return "SSL certificate validation failed"
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return "Request to the site failed"

    return None


def analyze_page_content(url):
    """Analyze the page content for suspicious meta tags or titles."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string if soup.title else ""

        print(f"Page title: {title}")
        if "login" in title.lower() or "secure" in title.lower():
            return "Suspicious page title detected"

        meta_tags = soup.find_all("meta")
        if any("phishing" in (tag.get("content", "").lower() or "") for tag in meta_tags):
            return "Suspicious meta tag detected"

        return None
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return "Unable to retrieve page content"


def check_shortened_url(url):
    """Check if the URL is a shortened URL, which could indicate phishing."""
    shortened_services = [
        "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly"
    ]

    parsed = urlparse(url)
    if any(service in parsed.netloc for service in shortened_services):
        print(f"Shortened URL detected: {parsed.netloc}")
        return "Shortened URL detected"

    return None


def check_suspicious_query_parameters(url):
    """Check for suspicious query parameters that are often used in phishing."""
    parsed_url = urlparse(url)
    suspicious_patterns = ["redirect", "token", "session", "login", "validate", "id="]

    query_params = unquote(parsed_url.query).lower()
    print(f"Query parameters: {query_params}")
    for pattern in suspicious_patterns:
        if pattern in query_params:
            print(f"Suspicious query parameter detected: {pattern}")
            return f"Suspicious query parameter detected: {pattern}"

    return None


def blacklist_check(url):
    """Check if the URL is flagged in VirusTotal's blacklist."""
    try:
        vt_api_key = "959da0d75d914574cf80d46f368195c53904b3d68bb85d10ef6b800cbc0af34d"
        base64_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{base64_url}"

        print(f"Checking blacklist on VirusTotal for: {url}")
        response = requests.get(vt_url, headers={"x-apikey": vt_api_key})
        if response.status_code == 200:
            data = response.json()
            print(f"VirusTotal response data: {data}")
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious",
                                                                                                            0)
            if malicious_count > 0:
                print("URL found in blacklist")
                return True
    except Exception as e:
        print(f"Error in blacklist check: {e}")

    return False


def phishing_link_scanner(url, trusted_domains_file):
    """Main function to scan the URL for phishing risk."""
    trusted_domains = load_trusted_domains(trusted_domains_file)
    if not trusted_domains:
        return "Error: Could not load trusted domains"

    if not is_valid_url(url):
        return "Invalid URL"

    findings = []

    if domain_mimic_check(url, trusted_domains):
        findings.append("Domain mimicry detected")

    tld_issue = check_uncommon_tld(url)
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
    trusted_domains_file = "domains.txt"  # Path to the trusted domains file
    print(phishing_link_scanner(test_url, trusted_domains_file))
