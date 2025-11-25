"""
Phone Analyzer Service.

Comprehensive phone number analysis combining parsing,
carrier lookup, reputation checks, and threat intelligence.
"""

import logging
import hashlib
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from django.conf import settings
from django.core.cache import cache

from algorithms.phone_parser import PhoneParser
from algorithms.risk_scorer import RiskScorer
from .threat_intelligence import ThreatIntelligenceService

logger = logging.getLogger('scamlytic.services.phone')


@dataclass
class PhoneAnalysisResult:
    """Complete phone number analysis result."""
    request_id: str
    scam_score: int
    verdict: str
    threat_type: str
    explanation: str
    recommended_action: str
    signals: List[str]
    confidence: float

    # Phone details
    phone_number: str
    e164_format: str = ''
    national_format: str = ''
    international_format: str = ''

    # Parsed info
    country_code: str = ''
    country_name: str = ''
    carrier: str = ''
    line_type: str = ''

    # Risk indicators
    is_valid: bool = False
    is_voip: bool = False
    is_toll_free: bool = False
    is_prepaid: bool = False

    # Reputation
    fraud_score: int = 0
    spam_score: int = 0
    report_count: int = 0
    in_blocklist: bool = False

    # Detailed analysis
    phone_analysis: Dict[str, Any] = field(default_factory=dict)
    reputation_data: Dict[str, Any] = field(default_factory=dict)

    processing_time_ms: int = 0


class PhoneAnalyzerService:
    """
    Advanced phone number analysis service.

    Combines phone parsing, carrier lookup, and reputation analysis.
    """

    def __init__(self):
        self.phone_parser = PhoneParser()
        self.risk_scorer = RiskScorer()
        self.threat_intel = ThreatIntelligenceService()

    def analyze(
        self,
        phone: str,
        default_region: str = 'US',
        deep_scan: bool = True,
        request_id: Optional[str] = None
    ) -> PhoneAnalysisResult:
        """
        Perform comprehensive phone number analysis.

        Args:
            phone: The phone number to analyze
            default_region: Default region for parsing
            deep_scan: Whether to perform reputation lookup
            request_id: Optional request ID

        Returns:
            PhoneAnalysisResult with complete analysis
        """
        start_time = time.time()

        # Generate request ID
        if not request_id:
            phone_hash = hashlib.md5(phone.encode()).hexdigest()[:8]
            request_id = f"phone_{phone_hash}_{int(time.time())}"

        # Initialize result
        result = PhoneAnalysisResult(
            request_id=request_id,
            scam_score=0,
            verdict='LOW_RISK',
            threat_type='LIKELY_SAFE',
            explanation='',
            recommended_action='',
            signals=[],
            confidence=0.5,
            phone_number=phone
        )

        try:
            # 1. Parse phone number
            phone_analysis = self.phone_parser.parse(phone, default_region)
            result.phone_analysis = {
                'original': phone_analysis.original_input,
                'normalized': phone_analysis.normalized,
                'e164_format': phone_analysis.e164_format,
                'national_format': phone_analysis.national_format,
                'international_format': phone_analysis.international_format,
                'is_valid': phone_analysis.is_valid,
                'is_possible': phone_analysis.is_possible,
                'country_code': phone_analysis.country_code,
                'national_number': phone_analysis.national_number,
                'country_name': phone_analysis.country_name,
                'number_type': phone_analysis.number_type,
                'carrier': phone_analysis.carrier,
                'is_voip': phone_analysis.is_voip,
                'is_toll_free': phone_analysis.is_toll_free,
                'is_premium_rate': phone_analysis.is_premium_rate,
                'risk_indicators': phone_analysis.risk_indicators,
            }

            # Copy key fields
            result.e164_format = phone_analysis.e164_format
            result.national_format = phone_analysis.national_format
            result.international_format = phone_analysis.international_format
            result.country_code = phone_analysis.country_code
            result.country_name = phone_analysis.country_name
            result.carrier = phone_analysis.carrier
            result.line_type = phone_analysis.number_type
            result.is_valid = phone_analysis.is_valid
            result.is_voip = phone_analysis.is_voip
            result.is_toll_free = phone_analysis.is_toll_free

            # 2. Check internal blocklist
            blocklist_check = self._check_blocklist(phone_analysis.e164_format)
            result.in_blocklist = blocklist_check.get('in_blocklist', False)
            if blocklist_check.get('in_blocklist'):
                result.report_count = blocklist_check.get('report_count', 0)

            # 3. Perform reputation lookup if enabled
            if deep_scan:
                try:
                    reputation = self.threat_intel.analyze_phone(phone_analysis.e164_format)
                    result.reputation_data = reputation

                    # Extract reputation scores
                    if reputation.get('fraud_score'):
                        result.fraud_score = reputation['fraud_score']
                    if reputation.get('is_suspicious'):
                        result.spam_score = 80

                    # Check for prepaid
                    sources = reputation.get('sources', {})
                    ipqs = sources.get('ipqualityscore', {})
                    if ipqs.get('available'):
                        result.is_prepaid = ipqs.get('prepaid', False)
                        if ipqs.get('voip'):
                            result.is_voip = True

                except Exception as e:
                    logger.error(f"Reputation lookup failed: {e}")
                    result.reputation_data = {'error': str(e)}

            # 4. Aggregate signals
            detected_signals = self._aggregate_signals(result, phone_analysis)

            # 5. Calculate final risk score
            risk_assessment = self.risk_scorer.calculate_score(
                detected_signals,
                additional_data={
                    'recent_reports': result.report_count,
                }
            )

            # 6. Determine threat type
            threat_type = self._determine_threat_type(result, detected_signals)

            # 7. Populate final result
            result.scam_score = risk_assessment.score
            result.verdict = risk_assessment.verdict
            result.threat_type = threat_type
            result.explanation = self._generate_explanation(result, phone_analysis)
            result.recommended_action = risk_assessment.recommended_action
            result.signals = detected_signals
            result.confidence = risk_assessment.confidence

        except Exception as e:
            logger.error(f"Phone analysis error: {e}")
            result.explanation = "Analysis encountered an error."
            result.recommended_action = "Exercise caution with this phone number."

        # Calculate processing time
        result.processing_time_ms = int((time.time() - start_time) * 1000)

        return result

    def _check_blocklist(self, phone_e164: str) -> Dict[str, Any]:
        """Check phone number against internal blocklist."""
        from apps.core.models import BlockedPhoneNumber

        try:
            blocked = BlockedPhoneNumber.objects.filter(
                phone_number=phone_e164,
                is_active=True
            ).first()

            if blocked:
                return {
                    'in_blocklist': True,
                    'threat_type': blocked.threat_type.code if blocked.threat_type else None,
                    'source': blocked.source,
                    'report_count': blocked.report_count,
                    'confidence': blocked.confidence,
                }

            return {'in_blocklist': False}

        except Exception as e:
            logger.warning(f"Blocklist check failed: {e}")
            return {'in_blocklist': False, 'error': str(e)}

    def _aggregate_signals(
        self,
        result: PhoneAnalysisResult,
        phone_analysis
    ) -> List[str]:
        """Aggregate all detected signals."""
        signals = set()

        # Phone parsing signals
        for indicator in phone_analysis.risk_indicators:
            if indicator == 'invalid_number':
                signals.add('invalid_number')
            elif indicator == 'voip_number':
                signals.add('voip_number')
            elif indicator == 'unknown_carrier':
                signals.add('unknown_carrier')

        # VoIP detection
        if result.is_voip:
            signals.add('voip_number')

        # Blocklist check
        if result.in_blocklist:
            signals.add('known_scam_number')

        # Fraud score
        if result.fraud_score >= 80:
            signals.add('high_fraud_score')
        elif result.fraud_score >= 50:
            signals.add('moderate_fraud_score')

        # Prepaid indicator
        if result.is_prepaid:
            signals.add('prepaid_number')

        # Invalid number
        if not result.is_valid:
            signals.add('invalid_number')

        # No issues found
        if not signals:
            signals.add('no_blocklist_match')

        return list(signals)

    def _determine_threat_type(
        self,
        result: PhoneAnalysisResult,
        signals: List[str]
    ) -> str:
        """Determine the primary threat type."""
        if 'known_scam_number' in signals:
            return 'KNOWN_SCAM'
        if 'high_fraud_score' in signals:
            return 'HIGH_RISK_NUMBER'
        if 'voip_number' in signals and result.scam_score > 50:
            return 'SUSPICIOUS_NUMBER'
        return 'LIKELY_SAFE'

    def _generate_explanation(
        self,
        result: PhoneAnalysisResult,
        phone_analysis
    ) -> str:
        """Generate human-readable explanation."""
        explanations = []

        if result.in_blocklist:
            explanations.append(
                f"This phone number has been reported {result.report_count} times "
                "and is in our scam database."
            )

        if result.is_voip:
            explanations.append(
                "This is a VoIP (internet-based) phone number, commonly used by scammers "
                "as they're easy to obtain anonymously."
            )

        if result.fraud_score >= 80:
            explanations.append(
                f"This number has a high fraud score ({result.fraud_score}/100) "
                "indicating suspicious activity."
            )
        elif result.fraud_score >= 50:
            explanations.append(
                f"This number has a moderate fraud score ({result.fraud_score}/100)."
            )

        if result.is_prepaid:
            explanations.append(
                "This appears to be a prepaid/disposable phone number."
            )

        if not result.is_valid:
            explanations.append(
                "This phone number appears to be invalid or incorrectly formatted."
            )

        if not explanations:
            if result.carrier:
                explanations.append(
                    f"This is a {result.line_type or 'phone'} number from {result.carrier} "
                    f"in {result.country_name}. No significant risk factors detected."
                )
            else:
                explanations.append("No significant risk factors detected for this number.")

        return " ".join(explanations)

    def quick_scan(self, phone: str) -> Dict[str, Any]:
        """
        Quick scan without deep reputation lookup.

        Returns basic analysis.
        """
        result = self.analyze(phone, deep_scan=False)
        return {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'is_valid': result.is_valid,
            'is_voip': result.is_voip,
            'carrier': result.carrier,
            'country': result.country_name,
            'signals': result.signals[:5],
            'processing_time_ms': result.processing_time_ms,
        }

    def validate_nigerian_phone(self, phone: str) -> Dict[str, Any]:
        """
        Validate and analyze a Nigerian phone number.
        """
        validation = self.phone_parser.validate_nigerian_phone(phone)

        if validation['is_valid']:
            # Perform full analysis
            result = self.analyze(phone, default_region='NG')
            return {
                **validation,
                'scam_score': result.scam_score,
                'verdict': result.verdict,
                'is_voip': result.is_voip,
                'in_blocklist': result.in_blocklist,
            }

        return validation

    def batch_analyze(
        self,
        phones: List[str],
        deep_scan: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple phone numbers.
        """
        results = []
        for phone in phones[:50]:  # Limit to 50 phones
            result = self.analyze(phone, deep_scan=deep_scan)
            results.append({
                'phone': phone,
                'formatted': result.e164_format,
                'scam_score': result.scam_score,
                'verdict': result.verdict,
                'is_valid': result.is_valid,
                'is_voip': result.is_voip,
                'carrier': result.carrier,
                'country': result.country_name,
            })
        return results
