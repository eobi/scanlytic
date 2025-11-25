"""
Threat Intelligence Service.

Aggregates data from multiple threat intelligence sources:
- VirusTotal
- Google Safe Browsing
- PhishTank
- URLhaus
- AbuseIPDB
- IPQualityScore
"""

import logging
import hashlib
import base64
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from django.conf import settings

from .base import BaseService, cached_result, require_api_key, ServiceException

logger = logging.getLogger('scamlytic.services.threat_intel')


class VirusTotalService(BaseService):
    """VirusTotal API integration."""

    service_name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self):
        super().__init__()
        self.api_key = settings.VIRUSTOTAL_API_KEY
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key
            })

    @cached_result(timeout=3600)
    @require_api_key('VIRUSTOTAL_API_KEY')
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL using VirusTotal.

        Returns detection stats, categories, and reputation.
        """
        try:
            # URL needs to be base64 encoded for VT API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            # Get URL analysis
            response = self._make_request(
                'GET',
                f"{self.base_url}/urls/{url_id}"
            )

            if response.status_code == 404:
                # URL not in database, submit for analysis
                return self._submit_url(url)

            if response.status_code != 200:
                logger.warning(f"VirusTotal returned {response.status_code}")
                return {'available': False, 'error': 'API error'}

            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            return {
                'available': True,
                'url': url,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_engines': sum(stats.values()),
                'categories': attributes.get('categories', {}),
                'reputation': attributes.get('reputation', 0),
                'times_submitted': attributes.get('times_submitted', 0),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'threat_names': attributes.get('threat_names', []),
            }

        except ServiceException:
            raise
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            return {'available': False, 'error': str(e)}

    def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis if not in database."""
        try:
            response = self._make_request(
                'POST',
                f"{self.base_url}/urls",
                data={'url': url}
            )

            if response.status_code == 200:
                return {
                    'available': True,
                    'status': 'submitted',
                    'message': 'URL submitted for analysis'
                }

            return {'available': False, 'error': 'Submission failed'}

        except Exception as e:
            return {'available': False, 'error': str(e)}

    @cached_result(timeout=3600)
    @require_api_key('VIRUSTOTAL_API_KEY')
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain using VirusTotal."""
        try:
            response = self._make_request(
                'GET',
                f"{self.base_url}/domains/{domain}"
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'Domain not found'}

            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            return {
                'available': True,
                'domain': domain,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'reputation': attributes.get('reputation', 0),
                'registrar': attributes.get('registrar', ''),
                'creation_date': attributes.get('creation_date'),
                'whois': attributes.get('whois', ''),
                'categories': attributes.get('categories', {}),
            }

        except Exception as e:
            logger.error(f"VirusTotal domain analysis failed: {e}")
            return {'available': False, 'error': str(e)}

    def analyze(self, url: str) -> Dict[str, Any]:
        """Main analysis method."""
        return self.analyze_url(url)


class GoogleSafeBrowsingService(BaseService):
    """Google Safe Browsing API integration."""

    service_name = "google_safebrowsing"
    base_url = "https://safebrowsing.googleapis.com/v4"

    def __init__(self):
        super().__init__()
        self.api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    @cached_result(timeout=1800)
    @require_api_key('GOOGLE_SAFE_BROWSING_API_KEY')
    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against Google Safe Browsing database.
        """
        try:
            payload = {
                "client": {
                    "clientId": "scamlytic",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            response = self._make_request(
                'POST',
                f"{self.base_url}/threatMatches:find",
                params={'key': self.api_key},
                json=payload
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'API error'}

            data = response.json()
            matches = data.get('matches', [])

            if matches:
                threats = []
                for match in matches:
                    threats.append({
                        'threat_type': match.get('threatType'),
                        'platform': match.get('platformType'),
                        'cache_duration': match.get('cacheDuration')
                    })

                return {
                    'available': True,
                    'is_malicious': True,
                    'threats': threats,
                    'threat_types': list(set(m['threat_type'] for m in threats))
                }

            return {
                'available': True,
                'is_malicious': False,
                'threats': [],
                'message': 'URL not found in threat database'
            }

        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")
            return {'available': False, 'error': str(e)}

    def analyze(self, url: str) -> Dict[str, Any]:
        return self.check_url(url)


class PhishTankService(BaseService):
    """PhishTank API integration."""

    service_name = "phishtank"
    base_url = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self):
        super().__init__()
        self.api_key = settings.PHISHTANK_API_KEY

    @cached_result(timeout=1800)
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against PhishTank database."""
        try:
            data = {
                'url': url,
                'format': 'json'
            }

            if self.api_key:
                data['app_key'] = self.api_key

            response = self._make_request(
                'POST',
                self.base_url,
                data=data
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'API error'}

            result = response.json().get('results', {})

            return {
                'available': True,
                'in_database': result.get('in_database', False),
                'is_phish': result.get('valid', False),
                'verified': result.get('verified', False),
                'verified_at': result.get('verified_at'),
                'phish_id': result.get('phish_id'),
                'phish_detail_url': result.get('phish_detail_page')
            }

        except Exception as e:
            logger.error(f"PhishTank check failed: {e}")
            return {'available': False, 'error': str(e)}

    def analyze(self, url: str) -> Dict[str, Any]:
        return self.check_url(url)


class URLhausService(BaseService):
    """URLhaus (abuse.ch) API integration."""

    service_name = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1"

    @cached_result(timeout=1800)
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against URLhaus database."""
        try:
            response = self._make_request(
                'POST',
                f"{self.base_url}/url/",
                data={'url': url}
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'API error'}

            data = response.json()

            if data.get('query_status') == 'no_results':
                return {
                    'available': True,
                    'in_database': False,
                    'is_malicious': False
                }

            return {
                'available': True,
                'in_database': True,
                'is_malicious': True,
                'threat': data.get('threat', ''),
                'url_status': data.get('url_status', ''),
                'date_added': data.get('date_added'),
                'tags': data.get('tags', []),
                'payloads': data.get('payloads', [])[:5]  # Limit payloads
            }

        except Exception as e:
            logger.error(f"URLhaus check failed: {e}")
            return {'available': False, 'error': str(e)}

    def analyze(self, url: str) -> Dict[str, Any]:
        return self.check_url(url)


class IPQualityScoreService(BaseService):
    """IPQualityScore API integration for URL and phone analysis."""

    service_name = "ipqualityscore"
    base_url = "https://ipqualityscore.com/api/json"

    def __init__(self):
        super().__init__()
        self.api_key = settings.IPQUALITYSCORE_API_KEY

    @cached_result(timeout=3600)
    @require_api_key('IPQUALITYSCORE_API_KEY')
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL using IPQualityScore."""
        try:
            import urllib.parse
            encoded_url = urllib.parse.quote(url, safe='')

            response = self._make_request(
                'GET',
                f"{self.base_url}/url/{self.api_key}/{encoded_url}",
                params={
                    'strictness': 1,
                    'fast': 'false'
                }
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'API error'}

            data = response.json()

            if not data.get('success', True):
                return {'available': False, 'error': data.get('message', 'API error')}

            return {
                'available': True,
                'unsafe': data.get('unsafe', False),
                'risk_score': data.get('risk_score', 0),
                'suspicious': data.get('suspicious', False),
                'phishing': data.get('phishing', False),
                'malware': data.get('malware', False),
                'parking': data.get('parking', False),
                'spamming': data.get('spamming', False),
                'adult': data.get('adult', False),
                'domain_rank': data.get('domain_rank', 0),
                'domain_age': data.get('domain_age', {}),
                'category': data.get('category', ''),
            }

        except Exception as e:
            logger.error(f"IPQualityScore URL check failed: {e}")
            return {'available': False, 'error': str(e)}

    @cached_result(timeout=3600)
    @require_api_key('IPQUALITYSCORE_API_KEY')
    def check_phone(self, phone: str) -> Dict[str, Any]:
        """Check phone number using IPQualityScore."""
        try:
            # Clean phone number
            clean_phone = ''.join(c for c in phone if c.isdigit() or c == '+')

            response = self._make_request(
                'GET',
                f"{self.base_url}/phone/{self.api_key}/{clean_phone}",
                params={
                    'strictness': 1,
                    'country': []
                }
            )

            if response.status_code != 200:
                return {'available': False, 'error': 'API error'}

            data = response.json()

            return {
                'available': True,
                'valid': data.get('valid', False),
                'formatted': data.get('formatted', ''),
                'local_format': data.get('local_format', ''),
                'fraud_score': data.get('fraud_score', 0),
                'recent_abuse': data.get('recent_abuse', False),
                'voip': data.get('VOIP', False),
                'prepaid': data.get('prepaid', False),
                'risky': data.get('risky', False),
                'active': data.get('active', False),
                'carrier': data.get('carrier', ''),
                'line_type': data.get('line_type', ''),
                'country': data.get('country', ''),
                'region': data.get('region', ''),
                'city': data.get('city', ''),
                'timezone': data.get('timezone', ''),
                'leaked': data.get('leaked', False),
                'spammer': data.get('spammer', False),
            }

        except Exception as e:
            logger.error(f"IPQualityScore phone check failed: {e}")
            return {'available': False, 'error': str(e)}

    def analyze(self, target: str, target_type: str = 'url') -> Dict[str, Any]:
        if target_type == 'phone':
            return self.check_phone(target)
        return self.check_url(target)


class ThreatIntelligenceService:
    """
    Aggregated threat intelligence from multiple sources.
    """

    def __init__(self):
        self.virustotal = VirusTotalService()
        self.google_safebrowsing = GoogleSafeBrowsingService()
        self.phishtank = PhishTankService()
        self.urlhaus = URLhausService()
        self.ipqualityscore = IPQualityScoreService()

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL using all available threat intelligence sources.
        """
        results = {
            'url': url,
            'domain': urlparse(url).netloc,
            'sources': {},
            'aggregate_score': 0,
            'is_malicious': False,
            'threat_types': [],
            'recommendations': []
        }

        # Gather results from all sources
        vt_result = self.virustotal.analyze_url(url)
        results['sources']['virustotal'] = vt_result

        gsb_result = self.google_safebrowsing.check_url(url)
        results['sources']['google_safebrowsing'] = gsb_result

        pt_result = self.phishtank.check_url(url)
        results['sources']['phishtank'] = pt_result

        uh_result = self.urlhaus.check_url(url)
        results['sources']['urlhaus'] = uh_result

        ipqs_result = self.ipqualityscore.check_url(url)
        results['sources']['ipqualityscore'] = ipqs_result

        # Aggregate results
        results = self._aggregate_url_results(results)

        return results

    def _aggregate_url_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate threat intelligence results into a unified score."""
        sources = results['sources']
        threat_types = set()
        scores = []
        is_malicious = False

        # VirusTotal
        vt = sources.get('virustotal', {})
        if vt.get('available'):
            malicious = vt.get('malicious', 0)
            total = vt.get('total_engines', 1)
            if malicious > 0:
                is_malicious = True
                threat_types.add('MALWARE_DETECTED')
            scores.append(min(100, (malicious / max(total, 1)) * 200))

        # Google Safe Browsing
        gsb = sources.get('google_safebrowsing', {})
        if gsb.get('available') and gsb.get('is_malicious'):
            is_malicious = True
            for threat in gsb.get('threat_types', []):
                if threat == 'SOCIAL_ENGINEERING':
                    threat_types.add('PHISHING_URL')
                elif threat == 'MALWARE':
                    threat_types.add('MALWARE_DETECTED')
            scores.append(95)

        # PhishTank
        pt = sources.get('phishtank', {})
        if pt.get('available') and pt.get('is_phish'):
            is_malicious = True
            threat_types.add('PHISHING_URL')
            scores.append(90)

        # URLhaus
        uh = sources.get('urlhaus', {})
        if uh.get('available') and uh.get('is_malicious'):
            is_malicious = True
            threat_types.add('MALWARE_DETECTED')
            scores.append(95)

        # IPQualityScore
        ipqs = sources.get('ipqualityscore', {})
        if ipqs.get('available'):
            risk_score = ipqs.get('risk_score', 0)
            scores.append(risk_score)
            if ipqs.get('phishing'):
                threat_types.add('PHISHING_URL')
                is_malicious = True
            if ipqs.get('malware'):
                threat_types.add('MALWARE_DETECTED')
                is_malicious = True

        # Calculate aggregate score
        if scores:
            results['aggregate_score'] = int(sum(scores) / len(scores))
        else:
            results['aggregate_score'] = 0

        results['is_malicious'] = is_malicious
        results['threat_types'] = list(threat_types)

        # Generate recommendations
        if is_malicious:
            results['recommendations'] = [
                'Do not visit this URL',
                'Do not enter any personal information',
                'Report this URL to relevant authorities',
                'Block this domain in your security tools'
            ]
        elif results['aggregate_score'] > 50:
            results['recommendations'] = [
                'Exercise caution with this URL',
                'Verify the source before proceeding',
                'Do not enter sensitive information'
            ]

        return results

    def analyze_phone(self, phone: str) -> Dict[str, Any]:
        """Analyze phone number using available services."""
        results = {
            'phone': phone,
            'sources': {},
            'fraud_score': 0,
            'is_suspicious': False,
            'risk_factors': []
        }

        # IPQualityScore
        ipqs_result = self.ipqualityscore.check_phone(phone)
        results['sources']['ipqualityscore'] = ipqs_result

        if ipqs_result.get('available'):
            results['fraud_score'] = ipqs_result.get('fraud_score', 0)

            if ipqs_result.get('voip'):
                results['risk_factors'].append('VoIP number detected')

            if ipqs_result.get('prepaid'):
                results['risk_factors'].append('Prepaid/disposable number')

            if ipqs_result.get('risky'):
                results['is_suspicious'] = True
                results['risk_factors'].append('Flagged as risky')

            if ipqs_result.get('spammer'):
                results['is_suspicious'] = True
                results['risk_factors'].append('Known spammer')

            if ipqs_result.get('recent_abuse'):
                results['is_suspicious'] = True
                results['risk_factors'].append('Recent abuse reports')

        return results

    def get_available_services(self) -> List[str]:
        """Get list of available threat intel services."""
        services = []
        if settings.VIRUSTOTAL_API_KEY:
            services.append('virustotal')
        if settings.GOOGLE_SAFE_BROWSING_API_KEY:
            services.append('google_safebrowsing')
        services.append('phishtank')  # No key required
        services.append('urlhaus')  # No key required
        if settings.IPQUALITYSCORE_API_KEY:
            services.append('ipqualityscore')
        return services
