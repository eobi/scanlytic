"""
URL Parser and Analyzer Module.

Deep URL analysis including structure, domain info,
redirect following, and security checks.
"""

import re
import ssl
import socket
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger('scamlytic.algorithms.url')


@dataclass
class URLAnalysisResult:
    """Result of URL analysis."""
    original_url: str
    normalized_url: str
    is_valid: bool = True
    domain: str = ''
    tld: str = ''
    subdomain: str = ''
    path: str = ''
    query_params: Dict[str, List[str]] = field(default_factory=dict)

    # Security
    is_https: bool = False
    has_valid_ssl: bool = False
    ssl_info: Dict[str, Any] = field(default_factory=dict)

    # Domain analysis
    is_ip_address: bool = False
    is_shortened: bool = False
    shortener_service: str = ''
    is_homograph: bool = False
    homograph_info: Dict[str, Any] = field(default_factory=dict)

    # Characteristics
    url_length: int = 0
    subdomain_count: int = 0
    special_char_count: int = 0
    has_suspicious_keywords: bool = False
    suspicious_keywords: List[str] = field(default_factory=list)

    # Risk indicators
    risk_indicators: List[str] = field(default_factory=list)
    risk_score: int = 0


class URLParser:
    """
    Advanced URL parsing and analysis.
    """

    # URL shortening services
    SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly',
        'shorturl.at', 'tiny.cc', 'bc.vc', 'v.gd', 'lnkd.in',
        't.me', 'fb.me', 'youtu.be', 'amzn.to', 'j.mp',
    }

    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'password', 'credential', 'suspended',
        'alert', 'urgent', 'limited', 'expire', 'click', 'action',
        'validate', 'authenticate', 'restore', 'unlock', 'security',
    ]

    # Known phishing TLDs
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
        'xyz', 'top', 'click', 'loan', 'work', 'date',
        'win', 'download', 'stream', 'racing', 'bid', 'trade',
        'party', 'cricket', 'science', 'review', 'accountant',
    }

    # Punycode/IDN patterns
    PUNYCODE_PREFIX = 'xn--'

    def __init__(self):
        self.ssl_context = ssl.create_default_context()

    def parse(self, url: str) -> URLAnalysisResult:
        """
        Parse and analyze a URL.

        Args:
            url: The URL to analyze

        Returns:
            URLAnalysisResult with complete analysis
        """
        result = URLAnalysisResult(
            original_url=url,
            normalized_url=url
        )

        # Normalize URL
        url = self._normalize_url(url)
        result.normalized_url = url
        result.url_length = len(url)

        # Parse URL components
        try:
            parsed = urlparse(url)
        except Exception as e:
            logger.error(f"URL parse error: {e}")
            result.is_valid = False
            result.risk_indicators.append('invalid_url_format')
            return result

        # Extract components
        result.is_https = parsed.scheme == 'https'
        result.domain = parsed.netloc.lower()
        result.path = parsed.path
        result.query_params = parse_qs(parsed.query)

        # Analyze domain
        self._analyze_domain(result)

        # Check for URL shortener
        self._check_shortener(result)

        # Check for suspicious keywords
        self._check_suspicious_keywords(result)

        # Check for IP address
        self._check_ip_address(result)

        # Check for homograph attacks
        self._check_homograph(result)

        # Analyze special characters
        self._analyze_special_chars(result)

        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)

        return result

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for analysis."""
        url = url.strip()

        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # URL decode
        try:
            url = unquote(url)
        except Exception:
            pass

        return url

    def _analyze_domain(self, result: URLAnalysisResult):
        """Analyze domain components."""
        domain = result.domain

        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        # Split into parts
        parts = domain.split('.')

        if len(parts) >= 2:
            result.tld = parts[-1]

            # Check for country code TLDs (e.g., .co.uk)
            if len(parts) >= 3 and len(parts[-2]) <= 3:
                result.tld = f"{parts[-2]}.{parts[-1]}"
                result.subdomain = '.'.join(parts[:-3]) if len(parts) > 3 else ''
            else:
                result.subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        result.subdomain_count = result.subdomain.count('.') + 1 if result.subdomain else 0

        # Check for suspicious TLD
        tld = result.tld.lower()
        if tld in self.SUSPICIOUS_TLDS:
            result.risk_indicators.append('suspicious_tld')

        # Check for excessive subdomains
        if result.subdomain_count > 3:
            result.risk_indicators.append('excessive_subdomains')

    def _check_shortener(self, result: URLAnalysisResult):
        """Check if URL uses a shortening service."""
        domain = result.domain.lower()

        for shortener in self.SHORTENERS:
            if domain == shortener or domain.endswith('.' + shortener):
                result.is_shortened = True
                result.shortener_service = shortener
                result.risk_indicators.append('url_shortener')
                break

    def _check_suspicious_keywords(self, result: URLAnalysisResult):
        """Check for suspicious keywords in URL."""
        url_lower = result.normalized_url.lower()
        found_keywords = []

        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)

        if found_keywords:
            result.has_suspicious_keywords = True
            result.suspicious_keywords = found_keywords
            if len(found_keywords) >= 3:
                result.risk_indicators.append('multiple_suspicious_keywords')
            else:
                result.risk_indicators.append('suspicious_keyword')

    def _check_ip_address(self, result: URLAnalysisResult):
        """Check if domain is an IP address."""
        domain = result.domain

        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            result.is_ip_address = True
            result.risk_indicators.append('ip_address_domain')
            return

        # IPv6 pattern (simplified)
        if domain.startswith('[') and domain.endswith(']'):
            result.is_ip_address = True
            result.risk_indicators.append('ip_address_domain')

    def _check_homograph(self, result: URLAnalysisResult):
        """Check for homograph/IDN attacks."""
        domain = result.domain

        # Check for punycode
        if self.PUNYCODE_PREFIX in domain.lower():
            result.is_homograph = True
            result.homograph_info['has_punycode'] = True
            result.risk_indicators.append('punycode_domain')

        # Check for mixed scripts
        has_latin = bool(re.search(r'[a-zA-Z]', domain))
        has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', domain))
        has_greek = bool(re.search(r'[\u0370-\u03FF]', domain))

        if sum([has_latin, has_cyrillic, has_greek]) > 1:
            result.is_homograph = True
            result.homograph_info['mixed_scripts'] = True
            result.risk_indicators.append('mixed_script_domain')

        # Check for look-alike characters
        lookalikes = {
            'о': 'o', 'а': 'a', 'е': 'e', 'р': 'p', 'с': 'c',
            'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j',
        }
        for char in domain:
            if char in lookalikes:
                result.is_homograph = True
                result.homograph_info['has_lookalike_chars'] = True
                result.risk_indicators.append('lookalike_chars')
                break

    def _analyze_special_chars(self, result: URLAnalysisResult):
        """Analyze special characters in URL."""
        url = result.normalized_url

        # Count special characters
        special_chars = re.findall(r'[@#%&=\+\-_~]', url)
        result.special_char_count = len(special_chars)

        # Check for @ sign (often used in phishing)
        if '@' in result.domain:
            result.risk_indicators.append('at_sign_in_domain')

        # Check for excessive hyphens (subdomain takeover indicator)
        if result.domain.count('-') >= 3:
            result.risk_indicators.append('excessive_hyphens')

        # Check for double extensions
        if re.search(r'\.\w{2,4}\.\w{2,4}/', url):
            result.risk_indicators.append('double_extension')

    def _calculate_risk_score(self, result: URLAnalysisResult) -> int:
        """Calculate risk score based on indicators."""
        score = 0

        # Risk weights
        weights = {
            'invalid_url_format': 20,
            'suspicious_tld': 15,
            'excessive_subdomains': 12,
            'url_shortener': 10,
            'multiple_suspicious_keywords': 20,
            'suspicious_keyword': 8,
            'ip_address_domain': 18,
            'punycode_domain': 25,
            'mixed_script_domain': 30,
            'lookalike_chars': 28,
            'at_sign_in_domain': 25,
            'excessive_hyphens': 10,
            'double_extension': 15,
        }

        for indicator in result.risk_indicators:
            score += weights.get(indicator, 5)

        # Additional factors
        if not result.is_https:
            score += 8

        if result.url_length > 100:
            score += 5

        if result.subdomain_count > 2:
            score += result.subdomain_count * 3

        return min(100, score)

    def check_ssl(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Check SSL certificate of a domain.

        Returns:
            Dictionary with SSL certificate information
        """
        result = {
            'has_ssl': False,
            'is_valid': False,
            'issuer': '',
            'subject': '',
            'expiry': None,
            'days_until_expiry': None,
            'error': None
        }

        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with self.ssl_context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    result['has_ssl'] = True
                    result['is_valid'] = True

                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer.get('organizationName', '')

                    # Extract subject
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['subject'] = subject.get('commonName', '')

                    # Extract expiry
                    expiry_str = cert.get('notAfter', '')
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        result['expiry'] = expiry.isoformat()
                        result['days_until_expiry'] = (expiry - datetime.now()).days

        except ssl.SSLError as e:
            result['error'] = f'SSL Error: {str(e)}'
        except socket.error as e:
            result['error'] = f'Connection Error: {str(e)}'
        except Exception as e:
            result['error'] = f'Error: {str(e)}'

        return result

    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text.

        Returns:
            List of extracted URLs
        """
        # Comprehensive URL pattern
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+'
            r'|www\.[^\s<>"{}|\\^`\[\]]+'
            r'|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|edu|gov|io|co|me|info|biz|xyz|top|online|site|app|dev|tech|ai|cloud)'
            r'(?:/[^\s<>"{}|\\^`\[\]]*)?',
            re.IGNORECASE
        )

        urls = url_pattern.findall(text)

        # Normalize and deduplicate
        normalized = []
        seen = set()
        for url in urls:
            url = url.rstrip('.,;:!?')  # Remove trailing punctuation
            if url.lower() not in seen:
                seen.add(url.lower())
                normalized.append(url)

        return normalized
