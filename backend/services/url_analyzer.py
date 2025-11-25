"""
URL Analyzer Service.

Comprehensive URL analysis combining URL parsing, WHOIS lookup,
threat intelligence, and security checks.
"""

import logging
import hashlib
import time
import socket
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse
from datetime import datetime

from django.conf import settings

from algorithms.url_parser import URLParser
from algorithms.pattern_matcher import DomainPatternMatcher
from algorithms.risk_scorer import RiskScorer
from .threat_intelligence import ThreatIntelligenceService
from .enhanced_threat_intel import EnhancedThreatIntelligence

logger = logging.getLogger('scamlytic.services.url')


@dataclass
class URLAnalysisResult:
    """Complete URL analysis result."""
    request_id: str
    scam_score: int
    verdict: str
    threat_type: str
    explanation: str
    recommended_action: str
    signals: List[str]
    confidence: float

    # URL details
    url: str
    final_url: str = ''
    domain: str = ''
    is_shortened: bool = False
    is_https: bool = False

    # Domain info
    domain_age_days: Optional[int] = None
    registrar: str = ''
    whois_data: Dict[str, Any] = field(default_factory=dict)

    # SSL info
    ssl_info: Dict[str, Any] = field(default_factory=dict)

    # Threat intelligence
    threat_intel: Dict[str, Any] = field(default_factory=dict)

    # Enhanced threat intelligence (additional sources)
    enhanced_threat_intel: Dict[str, Any] = field(default_factory=dict)

    # Detailed analysis
    url_analysis: Dict[str, Any] = field(default_factory=dict)
    domain_analysis: Dict[str, Any] = field(default_factory=dict)

    processing_time_ms: int = 0


class URLAnalyzerService:
    """
    Advanced URL analysis service.

    Combines URL parsing, threat intelligence, WHOIS lookup,
    and domain reputation analysis.
    """

    def __init__(self):
        self.url_parser = URLParser()
        self.domain_matcher = DomainPatternMatcher()
        self.risk_scorer = RiskScorer()
        self.threat_intel = ThreatIntelligenceService()
        self.enhanced_threat_intel = EnhancedThreatIntelligence()

    def analyze(
        self,
        url: str,
        follow_redirects: bool = True,
        deep_scan: bool = True,
        request_id: Optional[str] = None
    ) -> URLAnalysisResult:
        """
        Perform comprehensive URL analysis.

        Args:
            url: The URL to analyze
            follow_redirects: Whether to follow redirects
            deep_scan: Whether to perform deep analysis (WHOIS, threat intel)
            request_id: Optional request ID

        Returns:
            URLAnalysisResult with complete analysis
        """
        start_time = time.time()

        # Generate request ID
        if not request_id:
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            request_id = f"url_{url_hash}_{int(time.time())}"

        # Initialize result
        result = URLAnalysisResult(
            request_id=request_id,
            scam_score=0,
            verdict='LOW_RISK',
            threat_type='LIKELY_SAFE',
            explanation='',
            recommended_action='',
            signals=[],
            confidence=0.5,
            url=url
        )

        try:
            # 1. Parse and analyze URL structure
            url_analysis = self.url_parser.parse(url)
            result.url_analysis = {
                'normalized_url': url_analysis.normalized_url,
                'is_valid': url_analysis.is_valid,
                'is_https': url_analysis.is_https,
                'is_shortened': url_analysis.is_shortened,
                'shortener_service': url_analysis.shortener_service,
                'is_ip_address': url_analysis.is_ip_address,
                'is_homograph': url_analysis.is_homograph,
                'url_length': url_analysis.url_length,
                'subdomain_count': url_analysis.subdomain_count,
                'suspicious_keywords': url_analysis.suspicious_keywords,
                'risk_indicators': url_analysis.risk_indicators,
                'url_risk_score': url_analysis.risk_score,
            }

            result.domain = url_analysis.domain
            result.is_shortened = url_analysis.is_shortened
            result.is_https = url_analysis.is_https
            result.final_url = url_analysis.normalized_url

            # 2. Analyze domain patterns
            domain_analysis = self.domain_matcher.analyze_domain(url_analysis.domain)
            result.domain_analysis = {
                'is_legitimate': domain_analysis['is_legitimate'],
                'suspicious_tld': domain_analysis['suspicious_tld'],
                'brand_impersonation': domain_analysis['brand_impersonation'],
                'homograph_detected': domain_analysis['homograph_detected'],
                'risk_score': domain_analysis['risk_score'],
                'indicators': domain_analysis['indicators'],
            }

            # 3. Check SSL certificate
            if url_analysis.is_https:
                try:
                    ssl_info = self.url_parser.check_ssl(url_analysis.domain)
                    result.ssl_info = ssl_info
                except Exception as e:
                    logger.warning(f"SSL check failed: {e}")
                    result.ssl_info = {'error': str(e)}

            # 4. Perform deep scan if enabled
            if deep_scan:
                # WHOIS lookup
                try:
                    whois_data = self._get_whois_info(url_analysis.domain)
                    result.whois_data = whois_data
                    result.registrar = whois_data.get('registrar', '')
                    result.domain_age_days = whois_data.get('domain_age_days')
                except Exception as e:
                    logger.warning(f"WHOIS lookup failed: {e}")

                # Threat intelligence (primary sources: VirusTotal, Google Safe Browsing, etc.)
                try:
                    threat_intel_result = self.threat_intel.analyze_url(url)
                    result.threat_intel = {
                        'aggregate_score': threat_intel_result.get('aggregate_score', 0),
                        'is_malicious': threat_intel_result.get('is_malicious', False),
                        'threat_types': threat_intel_result.get('threat_types', []),
                        'sources': {
                            source: {
                                'available': data.get('available', False),
                                'is_malicious': data.get('is_malicious', data.get('malicious', 0) > 0),
                            }
                            for source, data in threat_intel_result.get('sources', {}).items()
                        }
                    }
                except Exception as e:
                    logger.error(f"Threat intel failed: {e}")
                    result.threat_intel = {'error': str(e)}

                # Enhanced threat intelligence (additional sources: ScamAdviser, OpenPhish, CryptoScamDB, etc.)
                try:
                    enhanced_result = self.enhanced_threat_intel.comprehensive_url_check(url)
                    result.enhanced_threat_intel = {
                        'overall_score': enhanced_result.get('overall_score', 0),
                        'is_malicious': enhanced_result.get('overall_score', 0) > 60,
                        'spamhaus': enhanced_result.get('spamhaus', {}),
                        'openphish': enhanced_result.get('openphish', {}),
                        'scamadviser': enhanced_result.get('scamadviser', {}),
                        'crypto_scam_db': enhanced_result.get('crypto_scam_db', {}),
                        'sources_checked': enhanced_result.get('sources_checked', []),
                    }

                    # Merge enhanced threat intel into primary if it finds issues
                    if enhanced_result.get('overall_score', 0) > 60:
                        result.threat_intel['is_malicious'] = True
                        if not result.threat_intel.get('threat_types'):
                            result.threat_intel['threat_types'] = []

                        # Add specific threat types from enhanced sources
                        if enhanced_result.get('openphish', {}).get('is_phishing'):
                            result.threat_intel['threat_types'].append('PHISHING_URL')
                        if enhanced_result.get('crypto_scam_db', {}).get('is_scam'):
                            result.threat_intel['threat_types'].append('CRYPTO_SCAM')
                        if enhanced_result.get('spamhaus', {}).get('is_blocklisted'):
                            result.threat_intel['threat_types'].append('BLOCKLISTED_DOMAIN')

                except Exception as e:
                    logger.warning(f"Enhanced threat intel failed: {e}")
                    result.enhanced_threat_intel = {'error': str(e)}

            # 5. Aggregate signals
            detected_signals = self._aggregate_signals(result, url_analysis, domain_analysis)

            # 6. Calculate final risk score
            risk_assessment = self.risk_scorer.calculate_score(
                detected_signals,
                additional_data={
                    'threat_intel_match': result.threat_intel.get('is_malicious', False),
                    'source_confirmations': sum(
                        1 for s in result.threat_intel.get('sources', {}).values()
                        if s.get('is_malicious')
                    ),
                }
            )

            # 7. Determine threat type
            threat_type = self._determine_threat_type(result, detected_signals)

            # 8. Populate final result
            result.scam_score = risk_assessment.score
            result.verdict = risk_assessment.verdict
            result.threat_type = threat_type
            result.explanation = self._generate_explanation(result, risk_assessment)
            result.recommended_action = risk_assessment.recommended_action
            result.signals = detected_signals
            result.confidence = risk_assessment.confidence

        except Exception as e:
            logger.error(f"URL analysis error: {e}")
            result.explanation = "Analysis encountered an error."
            result.recommended_action = "Exercise caution with this URL."

        # Calculate processing time
        result.processing_time_ms = int((time.time() - start_time) * 1000)

        return result

    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain."""
        try:
            import whois
            w = whois.whois(domain)

            result = {
                'registrar': w.registrar if hasattr(w, 'registrar') else '',
                'creation_date': None,
                'expiration_date': None,
                'domain_age_days': None,
                'name_servers': [],
                'status': [],
            }

            # Handle creation date
            if hasattr(w, 'creation_date') and w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    result['creation_date'] = creation.isoformat()
                    result['domain_age_days'] = (datetime.now() - creation).days

            # Handle expiration date
            if hasattr(w, 'expiration_date') and w.expiration_date:
                expiration = w.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                if isinstance(expiration, datetime):
                    result['expiration_date'] = expiration.isoformat()

            # Name servers
            if hasattr(w, 'name_servers') and w.name_servers:
                ns = w.name_servers
                if isinstance(ns, str):
                    ns = [ns]
                result['name_servers'] = list(ns)[:5]

            # Status
            if hasattr(w, 'status') and w.status:
                status = w.status
                if isinstance(status, str):
                    status = [status]
                result['status'] = list(status)[:5]

            return result

        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}

    def _aggregate_signals(
        self,
        result: URLAnalysisResult,
        url_analysis,
        domain_analysis: Dict[str, Any]
    ) -> List[str]:
        """Aggregate all detected signals."""
        signals = set()

        # URL structure signals
        for indicator in url_analysis.risk_indicators:
            if indicator == 'suspicious_tld':
                signals.add('suspicious_tld')
            elif indicator == 'url_shortener':
                signals.add('shortened_url')
            elif indicator in ['punycode_domain', 'mixed_script_domain', 'lookalike_chars']:
                signals.add('suspicious_url')
            elif indicator == 'ip_address_domain':
                signals.add('suspicious_url')

        # Domain analysis signals
        if domain_analysis.get('brand_impersonation'):
            signals.add('suspicious_url')

        if domain_analysis.get('homograph_detected'):
            signals.add('suspicious_url')

        if not domain_analysis.get('is_legitimate'):
            if domain_analysis.get('risk_score', 0) > 30:
                signals.add('suspicious_url')

        # SSL signals
        if not result.is_https:
            signals.add('no_ssl')
        elif result.ssl_info.get('is_valid'):
            signals.add('valid_ssl')

        # Domain age signals
        if result.domain_age_days is not None:
            if result.domain_age_days < 30:
                signals.add('new_domain')
            elif result.domain_age_days > 365:
                signals.add('established_domain')

        # Threat intelligence signals
        if result.threat_intel.get('is_malicious'):
            threat_types = result.threat_intel.get('threat_types', [])
            if 'MALWARE_DETECTED' in threat_types:
                signals.add('malware_detected')
            if 'PHISHING_URL' in threat_types:
                signals.add('phishing_confirmed')
            if 'CRYPTO_SCAM' in threat_types:
                signals.add('crypto_scam')
            if 'BLOCKLISTED_DOMAIN' in threat_types:
                signals.add('blocklisted_domain')

        # Enhanced threat intelligence signals
        enhanced = result.enhanced_threat_intel
        if enhanced and not enhanced.get('error'):
            if enhanced.get('spamhaus', {}).get('is_blocklisted'):
                signals.add('spamhaus_blocklisted')
            if enhanced.get('openphish', {}).get('is_phishing'):
                signals.add('openphish_detected')
            if enhanced.get('crypto_scam_db', {}).get('is_scam'):
                signals.add('crypto_scam_db_match')
            if enhanced.get('scamadviser', {}).get('trust_score', 100) < 50:
                signals.add('low_trust_score')

            # Overall enhanced score
            overall_score = enhanced.get('overall_score', 0)
            if overall_score > 80:
                signals.add('high_risk_enhanced_intel')
            elif overall_score > 60:
                signals.add('elevated_risk_enhanced_intel')

        # Add positive signals if applicable
        if domain_analysis.get('is_legitimate'):
            signals.add('known_brand')

        if not result.threat_intel.get('is_malicious') and not enhanced.get('is_malicious'):
            signals.add('no_blocklist_match')

        return list(signals)

    def _determine_threat_type(
        self,
        result: URLAnalysisResult,
        signals: List[str]
    ) -> str:
        """Determine the primary threat type."""
        if 'malware_detected' in signals:
            return 'MALWARE_DETECTED'
        if 'phishing_confirmed' in signals:
            return 'PHISHING_URL'
        if 'suspicious_url' in signals and result.scam_score > 50:
            return 'PHISHING_URL'
        if result.domain_analysis.get('brand_impersonation'):
            return 'IMPERSONATION'
        return 'LIKELY_SAFE'

    def _generate_explanation(
        self,
        result: URLAnalysisResult,
        risk_assessment
    ) -> str:
        """Generate human-readable explanation."""
        explanations = []

        if result.threat_intel.get('is_malicious'):
            explanations.append(
                "This URL has been flagged as malicious by multiple security vendors."
            )

        if result.domain_analysis.get('brand_impersonation'):
            brand = result.domain_analysis['brand_impersonation']
            explanations.append(
                f"This domain appears to impersonate {brand}."
            )

        if result.is_shortened:
            explanations.append(
                f"This is a shortened URL ({result.url_analysis.get('shortener_service', 'unknown service')}) "
                "which hides the final destination."
            )

        if result.domain_age_days is not None and result.domain_age_days < 30:
            explanations.append(
                f"This domain was registered only {result.domain_age_days} days ago."
            )

        if not result.is_https:
            explanations.append(
                "This URL does not use HTTPS encryption."
            )

        if result.domain_analysis.get('homograph_detected'):
            explanations.append(
                "This domain uses characters designed to look like a different domain."
            )

        if explanations:
            return " ".join(explanations)

        return risk_assessment.explanation

    def quick_scan(self, url: str) -> Dict[str, Any]:
        """
        Quick scan without deep analysis.

        Returns basic risk assessment.
        """
        result = self.analyze(url, deep_scan=False)
        return {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'domain': result.domain,
            'is_shortened': result.is_shortened,
            'is_https': result.is_https,
            'signals': result.signals[:5],
            'processing_time_ms': result.processing_time_ms,
        }

    def batch_analyze(
        self,
        urls: List[str],
        deep_scan: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple URLs.

        Args:
            urls: List of URLs to analyze
            deep_scan: Whether to perform deep analysis

        Returns:
            List of analysis results
        """
        results = []
        for url in urls[:50]:  # Limit to 50 URLs
            result = self.analyze(url, deep_scan=deep_scan)
            results.append({
                'url': url,
                'scam_score': result.scam_score,
                'verdict': result.verdict,
                'threat_type': result.threat_type,
                'domain': result.domain,
                'signals': result.signals,
            })
        return results
