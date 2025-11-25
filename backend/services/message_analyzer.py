"""
Message Analyzer Service.

Comprehensive message analysis combining NLP, pattern matching,
LLM analysis, and threat intelligence.
"""

import logging
import hashlib
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from django.conf import settings

from algorithms.text_analysis import TextAnalyzer, ScamPatternAnalyzer
from algorithms.pattern_matcher import PatternMatcher
from algorithms.risk_scorer import RiskScorer, ThreatClassifier
from algorithms.url_parser import URLParser
from algorithms.phone_parser import PhoneParser
from algorithms.modern_scam_detector import ModernScamDetector
from .llm_service import LLMService

logger = logging.getLogger('scamlytic.services.message')


@dataclass
class MessageAnalysisResult:
    """Complete message analysis result."""
    request_id: str
    scam_score: int
    verdict: str
    threat_type: str
    explanation: str
    recommended_action: str
    signals: List[str]
    confidence: float

    # Detailed analysis
    text_analysis: Dict[str, Any] = field(default_factory=dict)
    pattern_analysis: Dict[str, Any] = field(default_factory=dict)
    llm_analysis: Dict[str, Any] = field(default_factory=dict)
    urls_analysis: List[Dict[str, Any]] = field(default_factory=list)
    phones_analysis: List[Dict[str, Any]] = field(default_factory=list)

    processing_time_ms: int = 0


class MessageAnalyzerService:
    """
    Advanced message analysis service.

    Combines multiple analysis techniques for comprehensive scam detection.
    """

    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.pattern_analyzer = ScamPatternAnalyzer()
        self.pattern_matcher = PatternMatcher()
        self.risk_scorer = RiskScorer()
        self.url_parser = URLParser()
        self.phone_parser = PhoneParser()
        self.llm_service = LLMService()
        self.modern_scam_detector = ModernScamDetector()

    def analyze(
        self,
        content: str,
        context: str = 'unknown',
        sender_phone: Optional[str] = None,
        sender_email: Optional[str] = None,
        use_llm: bool = True,
        request_id: Optional[str] = None
    ) -> MessageAnalysisResult:
        """
        Perform comprehensive message analysis.

        Args:
            content: The message content to analyze
            context: Message context (whatsapp, sms, email, social)
            sender_phone: Optional sender phone number
            sender_email: Optional sender email
            use_llm: Whether to use LLM for analysis
            request_id: Optional request ID

        Returns:
            MessageAnalysisResult with complete analysis
        """
        start_time = time.time()

        # Generate request ID
        if not request_id:
            content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
            request_id = f"msg_{content_hash}_{int(time.time())}"

        # Initialize result
        result = MessageAnalysisResult(
            request_id=request_id,
            scam_score=0,
            verdict='LOW_RISK',
            threat_type='LIKELY_SAFE',
            explanation='',
            recommended_action='',
            signals=[],
            confidence=0.5
        )

        try:
            # 1. Basic text analysis
            text_result = self.text_analyzer.analyze(content)
            result.text_analysis = {
                'language': text_result.language,
                'word_count': text_result.word_count,
                'urgency_score': text_result.urgency_score,
                'manipulation_score': text_result.manipulation_score,
                'sentiment_score': text_result.sentiment_score,
                'grammar_score': text_result.grammar_score,
                'urls_found': text_result.urls_found,
                'phones_found': text_result.phones_found,
                'suspicious_phrases': text_result.suspicious_phrases,
            }

            # 2. Scam pattern detection
            pattern_result = self.pattern_analyzer.detect_patterns(content)
            result.pattern_analysis = {
                'nigerian_patterns': pattern_result['nigerian_patterns'],
                'scam_patterns': pattern_result['scam_patterns'],
                'detected_categories': pattern_result['detected_categories'],
                'total_matches': pattern_result['total_matches'],
            }

            # 3. Advanced pattern matching
            match_result = self.pattern_matcher.match(content)

            # 3.5. Modern scam detection (Pig Butchering, Sextortion, Quishing, etc.)
            modern_scam_results = self.modern_scam_detector.detect(content)
            if modern_scam_results:
                result.pattern_analysis['modern_scams'] = [
                    {
                        'scam_type': scam.scam_type,
                        'confidence': scam.confidence,
                        'matched_patterns': scam.matched_patterns,
                        'description': scam.description,
                        'severity': scam.severity,
                    }
                    for scam in modern_scam_results
                ]

            # Detect crypto wallets in text
            crypto_wallets = self.modern_scam_detector.detect_crypto_wallet(content)
            if crypto_wallets:
                result.pattern_analysis['crypto_wallets'] = crypto_wallets

            # Detect QR code context (Quishing indicators)
            qr_context = self.modern_scam_detector.detect_qr_code_context(content)
            if qr_context['has_qr_reference']:
                result.pattern_analysis['qr_code_context'] = qr_context

            # 4. Analyze extracted URLs
            if text_result.urls_found:
                for url in text_result.urls_found[:5]:  # Limit to 5 URLs
                    url_analysis = self.url_parser.parse(url)
                    result.urls_analysis.append({
                        'url': url,
                        'domain': url_analysis.domain,
                        'is_shortened': url_analysis.is_shortened,
                        'is_https': url_analysis.is_https,
                        'risk_score': url_analysis.risk_score,
                        'risk_indicators': url_analysis.risk_indicators,
                    })

            # 5. Analyze extracted phone numbers
            if text_result.phones_found:
                for phone in text_result.phones_found[:3]:  # Limit to 3 phones
                    phone_analysis = self.phone_parser.parse(phone)
                    result.phones_analysis.append({
                        'phone': phone,
                        'is_valid': phone_analysis.is_valid,
                        'country': phone_analysis.country_name,
                        'carrier': phone_analysis.carrier,
                        'is_voip': phone_analysis.is_voip,
                        'risk_score': phone_analysis.risk_score,
                    })

            # 6. LLM Analysis (if enabled and available)
            if use_llm and self.llm_service.is_available():
                try:
                    llm_result = self.llm_service.analyze_message(
                        content=content,
                        context=context,
                        additional_info={
                            'sender_phone': sender_phone,
                            'sender_email': sender_email,
                            'urls_found': text_result.urls_found,
                        }
                    )
                    result.llm_analysis = {
                        'is_scam': llm_result.is_scam,
                        'confidence': llm_result.confidence,
                        'threat_type': llm_result.threat_type,
                        'red_flags': llm_result.red_flags,
                        'explanation': llm_result.explanation,
                        'detailed_analysis': llm_result.detailed_analysis,
                    }
                except Exception as e:
                    logger.error(f"LLM analysis failed: {e}")
                    result.llm_analysis = {'error': str(e)}

            # 7. Aggregate signals
            detected_signals = self._aggregate_signals(
                text_result, pattern_result, match_result, result,
                modern_scam_results
            )

            # 8. Calculate final risk score
            risk_assessment = self.risk_scorer.calculate_score(
                detected_signals,
                additional_data={
                    'ai_confidence': result.llm_analysis.get('confidence', 0),
                    'ai_analysis_complete': 'error' not in result.llm_analysis,
                }
            )

            # 9. Classify threat type
            threat_type, threat_confidence = ThreatClassifier.classify(detected_signals)

            # Use LLM threat type if available and confident
            if result.llm_analysis.get('is_scam') and result.llm_analysis.get('confidence', 0) > 0.7:
                threat_type = result.llm_analysis.get('threat_type', threat_type)

            # Pattern-based threat type override
            if pattern_result['detected_categories']:
                pattern_threat, _ = self.pattern_analyzer.classify_threat(
                    content, pattern_result
                )
                if pattern_threat != 'LIKELY_SAFE':
                    threat_type = pattern_threat

            # Modern scam type override (highest priority for new scam types)
            if modern_scam_results:
                # Get the highest severity modern scam
                highest_severity_scam = max(
                    modern_scam_results,
                    key=lambda x: x.confidence * (3 if x.severity == 'critical' else 2 if x.severity == 'high' else 1)
                )
                if highest_severity_scam.confidence > 0.6:
                    threat_type = highest_severity_scam.scam_type.upper().replace(' ', '_')

            # 10. Populate final result
            result.scam_score = risk_assessment.score
            result.verdict = risk_assessment.verdict
            result.threat_type = threat_type
            result.explanation = self._generate_explanation(
                risk_assessment, result.llm_analysis, pattern_result
            )
            result.recommended_action = risk_assessment.recommended_action
            result.signals = detected_signals
            result.confidence = risk_assessment.confidence

        except Exception as e:
            logger.error(f"Message analysis error: {e}")
            result.explanation = "Analysis encountered an error. Please try again."
            result.recommended_action = "Exercise caution with this message."

        # Calculate processing time
        result.processing_time_ms = int((time.time() - start_time) * 1000)

        return result

    def _aggregate_signals(
        self,
        text_result,
        pattern_result: Dict[str, Any],
        match_result,
        result: MessageAnalysisResult,
        modern_scam_results: List = None
    ) -> List[str]:
        """Aggregate all detected signals."""
        signals = set()
        modern_scam_results = modern_scam_results or []

        # Text analysis signals
        if text_result.urgency_score > 0.7:
            signals.add('urgency_extreme')
        elif text_result.urgency_score > 0.4:
            signals.add('urgency_language')

        if text_result.manipulation_score > 0.6:
            signals.add('high_manipulation')

        if text_result.grammar_score < 0.5:
            signals.add('poor_grammar')

        # Pattern signals
        for category in pattern_result.get('detected_categories', []):
            if category == 'bvn_phishing':
                signals.add('bvn_phishing')
            elif category == 'nin_phishing':
                signals.add('nin_phishing')
            elif category == 'bank_impersonation':
                signals.add('account_threat')
            elif category == 'lottery_scam':
                signals.add('prize_claim')
            elif category == 'advance_fee':
                signals.add('inheritance_scam')

        # Pattern matcher signals
        for match in match_result.matches:
            if match.category == 'phishing':
                signals.add('password_request')
            elif match.category == 'financial':
                if 'wire' in match.matched_text.lower():
                    signals.add('wire_transfer_request')
                elif 'gift' in match.matched_text.lower():
                    signals.add('gift_card_request')
            elif match.category == 'threat':
                signals.add('account_threat')

        # URL signals
        for url_analysis in result.urls_analysis:
            if url_analysis['is_shortened']:
                signals.add('shortened_url')
            if url_analysis['risk_score'] > 50:
                signals.add('suspicious_url')

        # Phone signals
        for phone_analysis in result.phones_analysis:
            if phone_analysis.get('is_voip'):
                signals.add('voip_number')

        # LLM signals
        if result.llm_analysis.get('is_scam'):
            llm_threat = result.llm_analysis.get('threat_type', '')
            if llm_threat == 'BVN_PHISHING':
                signals.add('bvn_phishing')
            elif llm_threat == 'NIN_PHISHING':
                signals.add('nin_phishing')
            elif llm_threat == 'PHISHING_URL':
                signals.add('suspicious_url')

        # Modern scam signals
        for scam in modern_scam_results:
            scam_type = scam.scam_type.lower()
            if 'pig_butchering' in scam_type or 'pig butchering' in scam_type:
                signals.add('pig_butchering_scam')
            elif 'sextortion' in scam_type:
                signals.add('sextortion_attempt')
            elif 'quishing' in scam_type or 'qr' in scam_type:
                signals.add('qr_code_phishing')
            elif 'mfa' in scam_type or 'bypass' in scam_type:
                signals.add('mfa_bypass_attempt')
            elif 'crypto' in scam_type:
                signals.add('crypto_scam')
            elif 'romance' in scam_type:
                signals.add('romance_scam')
            elif 'ai_phishing' in scam_type or 'ai phishing' in scam_type:
                signals.add('ai_generated_phishing')

            # Add severity-based signals
            if scam.severity == 'critical' and scam.confidence > 0.7:
                signals.add('high_risk_modern_scam')
            elif scam.severity == 'high' and scam.confidence > 0.6:
                signals.add('elevated_risk_modern_scam')

        # Crypto wallet signals
        if result.pattern_analysis.get('crypto_wallets'):
            signals.add('crypto_wallet_detected')

        # QR code context signals
        qr_context = result.pattern_analysis.get('qr_code_context', {})
        if qr_context.get('has_qr_reference') and qr_context.get('risk_score', 0) > 50:
            signals.add('suspicious_qr_code')

        # Add positive signals if applicable
        if not signals:
            signals.add('no_blocklist_match')

        return list(signals)

    def _generate_explanation(
        self,
        risk_assessment,
        llm_analysis: Dict[str, Any],
        pattern_result: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation."""
        # Prefer LLM explanation if available and confident
        if llm_analysis.get('explanation') and llm_analysis.get('confidence', 0) > 0.6:
            return llm_analysis['explanation']

        # Fall back to risk assessment explanation
        return risk_assessment.explanation

    def quick_scan(self, content: str) -> Dict[str, Any]:
        """
        Quick scan without LLM for faster response.

        Returns basic risk assessment.
        """
        result = self.analyze(content, use_llm=False)
        return {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'signals': result.signals[:5],
            'processing_time_ms': result.processing_time_ms,
        }

    def batch_analyze(
        self,
        messages: List[Dict[str, str]],
        use_llm: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple messages.

        Args:
            messages: List of {'content': str, 'context': str} dicts
            use_llm: Whether to use LLM (slower but more accurate)

        Returns:
            List of analysis results
        """
        results = []
        for msg in messages[:100]:  # Limit to 100 messages
            result = self.analyze(
                content=msg.get('content', ''),
                context=msg.get('context', 'unknown'),
                use_llm=use_llm
            )
            results.append({
                'scam_score': result.scam_score,
                'verdict': result.verdict,
                'threat_type': result.threat_type,
                'explanation': result.explanation,
                'signals': result.signals,
            })
        return results
