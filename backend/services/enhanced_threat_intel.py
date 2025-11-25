"""
Enhanced Threat Intelligence with Modern Scam Databases.

Integrates with additional threat intelligence sources and
specialized scam detection databases.
"""

import logging
import re
import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from django.conf import settings
from django.core.cache import cache

from .base import BaseService, cached_result, require_api_key, ServiceException

logger = logging.getLogger('scamlytic.services.enhanced_threat_intel')


class HaveIBeenPwnedService(BaseService):
    """
    Have I Been Pwned API for checking breached credentials.
    Useful for detecting credential-stuffing and phishing context.
    """

    service_name = "haveibeenpwned"
    base_url = "https://haveibeenpwned.com/api/v3"

    def __init__(self):
        super().__init__()
        self.api_key = getattr(settings, 'HIBP_API_KEY', '')
        if self.api_key:
            self.session.headers.update({
                'hibp-api-key': self.api_key
            })

    @cached_result(timeout=86400)  # Cache for 24 hours
    def check_email_breaches(self, email: str) -> Dict[str, Any]:
        """Check if email has been in data breaches."""
        if not self.api_key:
            return {'available': False, 'error': 'API key not configured'}

        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/breachedaccount/{email}",
                params={'truncateResponse': 'true'}
            )

            if response.status_code == 404:
                return {
                    'available': True,
                    'breached': False,
                    'breach_count': 0
                }

            if response.status_code == 200:
                breaches = response.json()
                return {
                    'available': True,
                    'breached': True,
                    'breach_count': len(breaches),
                    'breaches': [b.get('Name') for b in breaches[:10]]
                }

            return {'available': False, 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            logger.error(f"HIBP check failed: {e}")
            return {'available': False, 'error': str(e)}


class SpamhausService(BaseService):
    """
    Spamhaus blocklist lookup for domains and IPs.
    """

    service_name = "spamhaus"

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain against Spamhaus DBL."""
        import socket

        try:
            # Query Spamhaus DBL via DNS
            query = f"{domain}.dbl.spamhaus.org"
            try:
                socket.gethostbyname(query)
                # If we get a response, it's listed
                return {
                    'available': True,
                    'listed': True,
                    'blocklist': 'Spamhaus DBL',
                    'reason': 'Domain found in Spamhaus Domain Block List'
                }
            except socket.gaierror:
                # Not listed
                return {
                    'available': True,
                    'listed': False
                }

        except Exception as e:
            logger.error(f"Spamhaus check failed: {e}")
            return {'available': False, 'error': str(e)}


class OpenPhishService(BaseService):
    """
    OpenPhish phishing feed integration.
    """

    service_name = "openphish"
    feed_url = "https://openphish.com/feed.txt"

    def __init__(self):
        super().__init__()
        self._phishing_urls = set()
        self._last_update = None

    def _update_feed(self):
        """Update phishing URL feed."""
        # Only update if older than 1 hour
        if self._last_update and (datetime.now() - self._last_update) < timedelta(hours=1):
            return

        try:
            response = self._make_request('GET', self.feed_url)
            if response.status_code == 200:
                self._phishing_urls = set(response.text.strip().split('\n'))
                self._last_update = datetime.now()
                logger.info(f"Updated OpenPhish feed: {len(self._phishing_urls)} URLs")
        except Exception as e:
            logger.error(f"OpenPhish feed update failed: {e}")

    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against OpenPhish feed."""
        self._update_feed()

        url_normalized = url.rstrip('/')

        if url_normalized in self._phishing_urls:
            return {
                'available': True,
                'is_phishing': True,
                'source': 'OpenPhish'
            }

        # Also check domain
        parsed = urlparse(url)
        domain = parsed.netloc

        for phish_url in self._phishing_urls:
            if domain in phish_url:
                return {
                    'available': True,
                    'is_phishing': True,
                    'source': 'OpenPhish',
                    'match_type': 'domain'
                }

        return {
            'available': True,
            'is_phishing': False
        }


class CryptoScamDBService(BaseService):
    """
    Crypto Scam Database integration.
    Tracks known scam wallets, domains, and fraud schemes.
    """

    service_name = "cryptoscamdb"
    base_url = "https://api.cryptoscamdb.org/v1"

    @cached_result(timeout=3600)
    def check_address(self, address: str) -> Dict[str, Any]:
        """Check crypto wallet address for scam association."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/check/{address}"
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    result = data.get('result', {})
                    return {
                        'available': True,
                        'is_scam': result.get('status') == 'blocked',
                        'entries': result.get('entries', []),
                        'type': result.get('type', 'unknown')
                    }

            return {
                'available': True,
                'is_scam': False
            }

        except Exception as e:
            logger.error(f"CryptoScamDB check failed: {e}")
            return {'available': False, 'error': str(e)}

    @cached_result(timeout=3600)
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain for crypto scam association."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/domain/{domain}"
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    result = data.get('result', {})
                    return {
                        'available': True,
                        'is_scam': result.get('status') == 'blocked',
                        'category': result.get('category', ''),
                        'subcategory': result.get('subcategory', ''),
                        'description': result.get('description', '')
                    }

            return {
                'available': True,
                'is_scam': False
            }

        except Exception as e:
            logger.error(f"CryptoScamDB domain check failed: {e}")
            return {'available': False, 'error': str(e)}


class ScamAdviserService(BaseService):
    """
    ScamAdviser API integration for website trust scoring.
    """

    service_name = "scamadviser"
    base_url = "https://api.scamadviser.com/v1"

    def __init__(self):
        super().__init__()
        self.api_key = getattr(settings, 'SCAMADVISER_API_KEY', '')

    @cached_result(timeout=3600)
    @require_api_key('SCAMADVISER_API_KEY')
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Get trust score for domain."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/trust",
                params={
                    'apikey': self.api_key,
                    'url': domain
                }
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'available': True,
                    'trust_score': data.get('trustScore', 50),
                    'risk_level': data.get('riskLevel', 'medium'),
                    'warnings': data.get('warnings', []),
                    'is_suspicious': data.get('trustScore', 50) < 30
                }

            return {'available': False, 'error': 'API error'}

        except Exception as e:
            logger.error(f"ScamAdviser check failed: {e}")
            return {'available': False, 'error': str(e)}


class AbuseIPDBService(BaseService):
    """
    AbuseIPDB integration for IP reputation checking.
    """

    service_name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        super().__init__()
        self.api_key = settings.ABUSEIPDB_API_KEY
        if self.api_key:
            self.session.headers.update({
                'Key': self.api_key
            })

    @cached_result(timeout=3600)
    @require_api_key('ABUSEIPDB_API_KEY')
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP address for abuse reports."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/check",
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': 90
                }
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'available': True,
                    'ip': ip,
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'is_tor': data.get('isTor', False),
                    'usage_type': data.get('usageType', '')
                }

            return {'available': False, 'error': 'API error'}

        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            return {'available': False, 'error': str(e)}


class ShodanService(BaseService):
    """
    Shodan integration for infrastructure analysis.
    Helps identify suspicious hosting and infrastructure.
    """

    service_name = "shodan"
    base_url = "https://api.shodan.io"

    def __init__(self):
        super().__init__()
        self.api_key = settings.SHODAN_API_KEY

    @cached_result(timeout=3600)
    @require_api_key('SHODAN_API_KEY')
    def lookup_host(self, ip: str) -> Dict[str, Any]:
        """Get Shodan data for an IP."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/shodan/host/{ip}",
                params={'key': self.api_key}
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'available': True,
                    'ip': ip,
                    'hostnames': data.get('hostnames', []),
                    'org': data.get('org', ''),
                    'asn': data.get('asn', ''),
                    'isp': data.get('isp', ''),
                    'country': data.get('country_code', ''),
                    'ports': data.get('ports', []),
                    'vulns': list(data.get('vulns', {}).keys())[:10],
                    'tags': data.get('tags', [])
                }

            return {'available': False, 'error': 'Host not found'}

        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
            return {'available': False, 'error': str(e)}


class SocialMediaScamChecker:
    """
    Check social media profiles and handles for scam indicators.
    """

    # Known patterns for scam social media handles
    SUSPICIOUS_PATTERNS = [
        r'support_\w+',
        r'\w+_support',
        r'official_\w+',
        r'\w+_official',
        r'help_\w+',
        r'\w+_helpdesk',
        r'customer_\w+',
        r'\w+verification',
        r'verify_\w+',
        r'\w+_team',
    ]

    # Platforms commonly used for scams
    HIGH_RISK_PLATFORMS = ['telegram', 'whatsapp']

    def analyze_handle(self, handle: str, platform: str = '') -> Dict[str, Any]:
        """Analyze social media handle for scam patterns."""
        handle_lower = handle.lower()
        indicators = []
        risk_score = 0

        # Check against suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.match(pattern, handle_lower):
                indicators.append(f'matches_suspicious_pattern: {pattern}')
                risk_score += 20

        # Check for impersonation keywords
        impersonation_keywords = [
            'official', 'support', 'help', 'verify', 'customer',
            'admin', 'team', 'service', 'care', 'assistant'
        ]
        for keyword in impersonation_keywords:
            if keyword in handle_lower:
                indicators.append(f'contains_impersonation_keyword: {keyword}')
                risk_score += 10

        # Check platform risk
        if platform.lower() in self.HIGH_RISK_PLATFORMS:
            indicators.append('high_risk_platform')
            risk_score += 15

        # Check for number padding (common in scam accounts)
        if re.search(r'\d{4,}', handle):
            indicators.append('excessive_numbers')
            risk_score += 10

        return {
            'handle': handle,
            'platform': platform,
            'risk_score': min(100, risk_score),
            'indicators': indicators,
            'is_suspicious': risk_score >= 30
        }


class EnhancedThreatIntelligence:
    """
    Enhanced threat intelligence aggregating multiple sources.
    """

    def __init__(self):
        self.hibp = HaveIBeenPwnedService()
        self.spamhaus = SpamhausService()
        self.openphish = OpenPhishService()
        self.cryptoscamdb = CryptoScamDBService()
        self.scamadviser = ScamAdviserService()
        self.abuseipdb = AbuseIPDBService()
        self.shodan = ShodanService()
        self.social_checker = SocialMediaScamChecker()

    def comprehensive_url_check(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive URL threat check across all sources.
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        results = {
            'url': url,
            'domain': domain,
            'sources': {},
            'is_malicious': False,
            'threat_score': 0,
            'threats_detected': []
        }

        # OpenPhish
        openphish_result = self.openphish.check_url(url)
        results['sources']['openphish'] = openphish_result
        if openphish_result.get('is_phishing'):
            results['is_malicious'] = True
            results['threat_score'] += 40
            results['threats_detected'].append('phishing')

        # Spamhaus
        spamhaus_result = self.spamhaus.check_domain(domain)
        results['sources']['spamhaus'] = spamhaus_result
        if spamhaus_result.get('listed'):
            results['is_malicious'] = True
            results['threat_score'] += 35
            results['threats_detected'].append('spam_domain')

        # CryptoScamDB (for crypto-related URLs)
        cryptoscam_result = self.cryptoscamdb.check_domain(domain)
        results['sources']['cryptoscamdb'] = cryptoscam_result
        if cryptoscam_result.get('is_scam'):
            results['is_malicious'] = True
            results['threat_score'] += 45
            results['threats_detected'].append('crypto_scam')

        # ScamAdviser
        scamadviser_result = self.scamadviser.check_domain(domain)
        results['sources']['scamadviser'] = scamadviser_result
        if scamadviser_result.get('is_suspicious'):
            results['threat_score'] += 25
            results['threats_detected'].append('low_trust_score')

        # Normalize score
        results['threat_score'] = min(100, results['threat_score'])

        return results

    def check_crypto_address(self, address: str) -> Dict[str, Any]:
        """Check cryptocurrency address for scam association."""
        return self.cryptoscamdb.check_address(address)

    def check_email_reputation(self, email: str) -> Dict[str, Any]:
        """Check email address reputation."""
        results = {
            'email': email,
            'is_suspicious': False,
            'risk_factors': []
        }

        # Check for breaches
        hibp_result = self.hibp.check_email_breaches(email)
        if hibp_result.get('breached'):
            results['breached'] = True
            results['breach_count'] = hibp_result.get('breach_count', 0)

        # Analyze email domain
        domain = email.split('@')[-1] if '@' in email else ''
        if domain:
            # Check if domain is from suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    results['is_suspicious'] = True
                    results['risk_factors'].append(f'suspicious_tld: {tld}')

            # Check domain reputation
            spamhaus_result = self.spamhaus.check_domain(domain)
            if spamhaus_result.get('listed'):
                results['is_suspicious'] = True
                results['risk_factors'].append('domain_in_spamhaus')

        return results

    def check_social_handle(self, handle: str, platform: str = '') -> Dict[str, Any]:
        """Check social media handle for scam patterns."""
        return self.social_checker.analyze_handle(handle, platform)

    def get_available_services(self) -> List[str]:
        """List available threat intelligence services."""
        services = ['openphish', 'spamhaus', 'cryptoscamdb']

        if getattr(settings, 'HIBP_API_KEY', ''):
            services.append('haveibeenpwned')
        if getattr(settings, 'SCAMADVISER_API_KEY', ''):
            services.append('scamadviser')
        if settings.ABUSEIPDB_API_KEY:
            services.append('abuseipdb')
        if settings.SHODAN_API_KEY:
            services.append('shodan')

        return services
