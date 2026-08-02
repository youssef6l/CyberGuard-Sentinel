import re
import socket
import ssl
import urllib.parse
import datetime

# ========== Suspicious Patterns ==========
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'account', 'secure', 'banking',
    'paypal', 'password', 'credential', 'wallet', 'crypto', 'free', 'prize',
    'winner', 'click', 'confirm', 'suspend', 'urgent', 'alert', 'limited',
    'invoice', 'download', 'setup', 'install', 'exe', 'zip', 'rar'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top', '.xyz', '.info', '.click']

KNOWN_MALICIOUS_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address as host
    r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',  # URL shorteners
    r'[a-z0-9]{20,}\.',  # Very long random subdomain
]

# ========== Main Scanner ==========
def scan_url(url: str) -> dict:
    """
    Scan a URL for phishing and malicious indicators.
    Returns a detailed result dict.
    """
    result = {
        'url': url,
        'normalized_url': '',
        'domain': '',
        'scheme': '',
        'is_https': False,
        'ssl_valid': False,
        'ssl_expiry': None,
        'ip_address': '',
        'risk_score': 0,
        'risk_level': 'Unknown',
        'flags': [],
        'suspicious_keywords': [],
        'url_length': len(url),
        'has_suspicious_tld': False,
        'uses_ip_as_host': False,
        'is_url_shortener': False,
        'redirect_check': 'Not checked',
        'summary': ''
    }

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    result['normalized_url'] = url

    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
        result['scheme'] = parsed.scheme
        result['domain'] = parsed.netloc
        result['is_https'] = parsed.scheme == 'https'
        full_url_lower = url.lower()
        path_lower = (parsed.path + '?' + parsed.query).lower()
    except Exception as e:
        result['flags'].append(f'URL parse error: {str(e)}')
        result['risk_level'] = 'Error'
        return result

    # === Check 1: HTTPS ===
    if not result['is_https']:
        result['flags'].append('No HTTPS (unencrypted connection)')
        result['risk_score'] += 15

    # === Check 2: SSL Certificate ===
    if result['is_https']:
        ssl_info = _check_ssl(parsed.netloc)
        result['ssl_valid'] = ssl_info['valid']
        result['ssl_expiry'] = ssl_info['expiry']
        if not ssl_info['valid']:
            result['flags'].append(f"SSL issue: {ssl_info['error']}")
            result['risk_score'] += 25

    # === Check 3: IP as Host ===
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(parsed.netloc.split(':')[0]):
        result['uses_ip_as_host'] = True
        result['flags'].append('Direct IP address used instead of domain (high risk)')
        result['risk_score'] += 30

    # === Check 4: Suspicious TLD ===
    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            result['has_suspicious_tld'] = True
            result['flags'].append(f'Suspicious TLD detected: {tld}')
            result['risk_score'] += 20
            break

    # === Check 5: URL Shortener ===
    shortener_pattern = re.compile(r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|is\.gd|short\.link', re.I)
    if shortener_pattern.search(parsed.netloc):
        result['is_url_shortener'] = True
        result['flags'].append('URL shortener detected — hides real destination')
        result['risk_score'] += 20

    # === Check 6: Suspicious Keywords ===
    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_url_lower:
            found_keywords.append(kw)
    if found_keywords:
        result['suspicious_keywords'] = found_keywords
        result['flags'].append(f'Suspicious keywords found: {", ".join(found_keywords)}')
        result['risk_score'] += min(len(found_keywords) * 5, 25)

    # === Check 7: URL Length ===
    if len(url) > 100:
        result['flags'].append(f'Unusually long URL ({len(url)} chars)')
        result['risk_score'] += 10

    # === Check 8: Multiple subdomains ===
    subdomain_count = parsed.netloc.count('.')
    if subdomain_count >= 4:
        result['flags'].append(f'Excessive subdomains ({subdomain_count} dots) — possible domain spoofing')
        result['risk_score'] += 15

    # === Check 9: @ symbol in URL ===
    if '@' in url:
        result['flags'].append('@ symbol in URL — can be used to deceive browsers')
        result['risk_score'] += 30

    # === Check 10: Double slashes or encoded chars ===
    if '//' in parsed.path or '%' in url[8:]:
        result['flags'].append('Encoded characters or double slashes detected in path')
        result['risk_score'] += 10

    # === Check 11: Homoglyph / Unicode trick ===
    if any(ord(c) > 127 for c in parsed.netloc):
        result['flags'].append('Non-ASCII characters in domain — possible homoglyph attack')
        result['risk_score'] += 35

    # === Check 12: Long random subdomain ===
    long_subdomain = re.compile(r'[a-z0-9]{20,}\.')
    if long_subdomain.search(parsed.netloc):
        result['flags'].append('Very long random-looking subdomain detected')
        result['risk_score'] += 15

    # === Resolve IP ===
    try:
        hostname = parsed.netloc.split(':')[0]
        result['ip_address'] = socket.gethostbyname(hostname)
    except Exception:
        result['ip_address'] = 'Could not resolve'
        result['flags'].append('Domain could not be resolved (DNS failure or fake domain)')
        result['risk_score'] += 20

    # === Clamp score ===
    result['risk_score'] = min(result['risk_score'], 100)

    # === Risk Level ===
    if result['risk_score'] >= 70:
        result['risk_level'] = 'Critical'
    elif result['risk_score'] >= 45:
        result['risk_level'] = 'High'
    elif result['risk_score'] >= 20:
        result['risk_level'] = 'Medium'
    elif result['risk_score'] > 0:
        result['risk_level'] = 'Low'
    else:
        result['risk_level'] = 'Safe'

    # === Summary ===
    flag_count = len(result['flags'])
    result['summary'] = (
        f"URL scored {result['risk_score']}/100 risk. "
        f"Found {flag_count} indicator(s). "
        f"Risk level: {result['risk_level']}."
    )

    return result


def _check_ssl(hostname: str) -> dict:
    """Check SSL certificate validity and expiry."""
    info = {'valid': False, 'expiry': None, 'error': ''}
    host = hostname.split(':')[0]
    port = 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get('notAfter', '')
                if expiry_str:
                    expiry = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    info['expiry'] = expiry.strftime('%Y-%m-%d')
                    if expiry > datetime.datetime.utcnow():
                        info['valid'] = True
                    else:
                        info['error'] = 'Certificate expired'
                else:
                    info['valid'] = True
    except ssl.SSLCertVerificationError as e:
        info['error'] = f'SSL verification failed: {str(e)[:60]}'
    except Exception as e:
        info['error'] = f'SSL check failed: {str(e)[:60]}'
    return info
