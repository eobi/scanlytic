"""
Risk Scoring Module.

Advanced risk scoring algorithms combining multiple signals
into a unified scam score.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger('scamlytic.algorithms.risk')


class RiskLevel(Enum):
    """Risk level classification."""
    LOW = 'LOW_RISK'
    MODERATE = 'MODERATE_RISK'
    HIGH = 'HIGH_RISK'
    CRITICAL = 'CRITICAL_RISK'


class SignalCategory(Enum):
    """Signal categories for scoring."""
    CRITICAL = 'critical'
    HIGH = 'high'
    MODERATE = 'moderate'
    LOW = 'low'
    POSITIVE = 'positive'  # Signals that reduce risk


@dataclass
class Signal:
    """A risk signal."""
    code: str
    name: str
    category: SignalCategory
    weight: int
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""
    score: int
    level: RiskLevel
    verdict: str
    signals: List[Signal]
    explanation: str
    recommended_action: str
    confidence: float
    breakdown: Dict[str, Any]


class RiskScorer:
    """
    Advanced risk scoring engine.

    Combines multiple signals into a weighted score
    with explanation generation.
    """

    # Signal definitions
    SIGNALS = {
        # Critical signals (immediate red flags)
        'bvn_phishing': Signal(
            'bvn_phishing', 'BVN Phishing Attempt',
            SignalCategory.CRITICAL, 40,
            'Request for Bank Verification Number detected'
        ),
        'nin_phishing': Signal(
            'nin_phishing', 'NIN Phishing Attempt',
            SignalCategory.CRITICAL, 40,
            'Request for National ID Number detected'
        ),
        'password_request': Signal(
            'password_request', 'Password Request',
            SignalCategory.CRITICAL, 35,
            'Suspicious request for password'
        ),
        'card_request': Signal(
            'card_request', 'Card Details Request',
            SignalCategory.CRITICAL, 35,
            'Request for credit/debit card information'
        ),
        'malware_detected': Signal(
            'malware_detected', 'Malware Detected',
            SignalCategory.CRITICAL, 45,
            'URL/content flagged for malware by security vendors'
        ),
        'phishing_confirmed': Signal(
            'phishing_confirmed', 'Confirmed Phishing',
            SignalCategory.CRITICAL, 45,
            'URL confirmed as phishing by threat intel'
        ),

        # Modern scam critical signals
        'pig_butchering_scam': Signal(
            'pig_butchering_scam', 'Pig Butchering Scam',
            SignalCategory.CRITICAL, 42,
            'Investment/romance combo scam pattern detected'
        ),
        'sextortion_attempt': Signal(
            'sextortion_attempt', 'Sextortion Attempt',
            SignalCategory.CRITICAL, 45,
            'Blackmail/extortion threat with intimate content'
        ),
        'mfa_bypass_attempt': Signal(
            'mfa_bypass_attempt', 'MFA Bypass Attempt',
            SignalCategory.CRITICAL, 40,
            'Attempt to bypass multi-factor authentication'
        ),
        'high_risk_modern_scam': Signal(
            'high_risk_modern_scam', 'High Risk Modern Scam',
            SignalCategory.CRITICAL, 38,
            'Modern scam pattern with high confidence'
        ),

        # Enhanced threat intel critical signals
        'spamhaus_blocklisted': Signal(
            'spamhaus_blocklisted', 'Spamhaus Blocklisted',
            SignalCategory.CRITICAL, 40,
            'Domain is blocklisted by Spamhaus'
        ),
        'openphish_detected': Signal(
            'openphish_detected', 'OpenPhish Detection',
            SignalCategory.CRITICAL, 42,
            'URL detected in OpenPhish phishing feed'
        ),
        'crypto_scam_db_match': Signal(
            'crypto_scam_db_match', 'Crypto Scam Database Match',
            SignalCategory.CRITICAL, 40,
            'Domain/wallet found in crypto scam database'
        ),

        # High severity signals
        'account_threat': Signal(
            'account_threat', 'Account Suspension Threat',
            SignalCategory.HIGH, 25,
            'Threatening account suspension or closure'
        ),
        'prize_claim': Signal(
            'prize_claim', 'Prize Claim Scam',
            SignalCategory.HIGH, 28,
            'Lottery/prize claim language detected'
        ),
        'inheritance_scam': Signal(
            'inheritance_scam', 'Inheritance Scam',
            SignalCategory.HIGH, 30,
            'Inheritance or unclaimed funds narrative'
        ),
        'urgency_extreme': Signal(
            'urgency_extreme', 'Extreme Urgency',
            SignalCategory.HIGH, 25,
            'Extreme time pressure tactics'
        ),
        'known_scam_number': Signal(
            'known_scam_number', 'Known Scam Number',
            SignalCategory.HIGH, 35,
            'Phone number in scam database'
        ),
        'voip_number': Signal(
            'voip_number', 'VoIP Number',
            SignalCategory.HIGH, 20,
            'VoIP/Internet number detected'
        ),
        'image_found_elsewhere': Signal(
            'image_found_elsewhere', 'Image Found Elsewhere',
            SignalCategory.HIGH, 30,
            'Profile image found on other websites'
        ),
        'ai_generated_image': Signal(
            'ai_generated_image', 'AI Generated Image',
            SignalCategory.HIGH, 28,
            'Profile image appears to be AI-generated'
        ),

        # Modern scam high severity signals
        'qr_code_phishing': Signal(
            'qr_code_phishing', 'QR Code Phishing (Quishing)',
            SignalCategory.HIGH, 30,
            'QR code used in suspected phishing attempt'
        ),
        'crypto_scam': Signal(
            'crypto_scam', 'Cryptocurrency Scam',
            SignalCategory.HIGH, 28,
            'Cryptocurrency fraud pattern detected'
        ),
        'romance_scam': Signal(
            'romance_scam', 'Romance Scam',
            SignalCategory.HIGH, 28,
            'Romance scam manipulation pattern detected'
        ),
        'ai_generated_phishing': Signal(
            'ai_generated_phishing', 'AI-Generated Phishing',
            SignalCategory.HIGH, 32,
            'AI-generated phishing content detected'
        ),
        'elevated_risk_modern_scam': Signal(
            'elevated_risk_modern_scam', 'Elevated Risk Modern Scam',
            SignalCategory.HIGH, 25,
            'Modern scam pattern with moderate confidence'
        ),
        'high_risk_enhanced_intel': Signal(
            'high_risk_enhanced_intel', 'High Risk Enhanced Intel',
            SignalCategory.HIGH, 28,
            'Multiple enhanced threat intel sources flag this'
        ),
        'blocklisted_domain': Signal(
            'blocklisted_domain', 'Blocklisted Domain',
            SignalCategory.HIGH, 30,
            'Domain found in security blocklists'
        ),

        # Moderate severity signals
        'suspicious_url': Signal(
            'suspicious_url', 'Suspicious URL',
            SignalCategory.MODERATE, 18,
            'URL shows suspicious characteristics'
        ),
        'shortened_url': Signal(
            'shortened_url', 'Shortened URL',
            SignalCategory.MODERATE, 12,
            'URL shortening service used'
        ),
        'urgency_language': Signal(
            'urgency_language', 'Urgency Language',
            SignalCategory.MODERATE, 15,
            'Urgency/pressure language detected'
        ),
        'wire_transfer_request': Signal(
            'wire_transfer_request', 'Wire Transfer Request',
            SignalCategory.MODERATE, 18,
            'Request for wire transfer payment'
        ),
        'gift_card_request': Signal(
            'gift_card_request', 'Gift Card Request',
            SignalCategory.MODERATE, 18,
            'Request for gift card payment'
        ),
        'new_domain': Signal(
            'new_domain', 'Recently Registered Domain',
            SignalCategory.MODERATE, 15,
            'Domain registered less than 30 days ago'
        ),
        'no_ssl': Signal(
            'no_ssl', 'No SSL Certificate',
            SignalCategory.MODERATE, 12,
            'Website lacks SSL/HTTPS encryption'
        ),
        'profile_inconsistencies': Signal(
            'profile_inconsistencies', 'Profile Inconsistencies',
            SignalCategory.MODERATE, 15,
            'Profile information appears inconsistent'
        ),

        # Modern scam moderate severity signals
        'suspicious_qr_code': Signal(
            'suspicious_qr_code', 'Suspicious QR Code Context',
            SignalCategory.MODERATE, 15,
            'QR code mentioned in suspicious context'
        ),
        'crypto_wallet_detected': Signal(
            'crypto_wallet_detected', 'Crypto Wallet Detected',
            SignalCategory.MODERATE, 12,
            'Cryptocurrency wallet address in message'
        ),
        'low_trust_score': Signal(
            'low_trust_score', 'Low Trust Score',
            SignalCategory.MODERATE, 18,
            'Website has low trust score from reputation services'
        ),
        'elevated_risk_enhanced_intel': Signal(
            'elevated_risk_enhanced_intel', 'Elevated Risk Enhanced Intel',
            SignalCategory.MODERATE, 15,
            'Some enhanced threat intel sources raise concerns'
        ),
        'high_manipulation': Signal(
            'high_manipulation', 'High Manipulation Score',
            SignalCategory.MODERATE, 18,
            'Message contains manipulative language patterns'
        ),

        # Low severity signals
        'generic_greeting': Signal(
            'generic_greeting', 'Generic Greeting',
            SignalCategory.LOW, 8,
            'Generic greeting instead of personalized'
        ),
        'poor_grammar': Signal(
            'poor_grammar', 'Poor Grammar',
            SignalCategory.LOW, 7,
            'Multiple grammar/spelling issues'
        ),
        'suspicious_tld': Signal(
            'suspicious_tld', 'Suspicious TLD',
            SignalCategory.LOW, 10,
            'Domain uses suspicious top-level domain'
        ),
        'low_engagement': Signal(
            'low_engagement', 'Low Engagement',
            SignalCategory.LOW, 8,
            'Profile has suspiciously low engagement'
        ),

        # Positive signals (reduce risk)
        'valid_ssl': Signal(
            'valid_ssl', 'Valid SSL Certificate',
            SignalCategory.POSITIVE, -10,
            'Website has valid SSL certificate'
        ),
        'known_brand': Signal(
            'known_brand', 'Known Brand Domain',
            SignalCategory.POSITIVE, -15,
            'Domain belongs to a known legitimate brand'
        ),
        'established_domain': Signal(
            'established_domain', 'Established Domain',
            SignalCategory.POSITIVE, -10,
            'Domain has been active for over 1 year'
        ),
        'verified_account': Signal(
            'verified_account', 'Verified Account',
            SignalCategory.POSITIVE, -15,
            'Social media account is verified'
        ),
        'no_blocklist_match': Signal(
            'no_blocklist_match', 'Not in Blocklist',
            SignalCategory.POSITIVE, -5,
            'Not found in threat databases'
        ),
    }

    # Thresholds for risk levels
    THRESHOLDS = {
        RiskLevel.LOW: (0, 24),
        RiskLevel.MODERATE: (25, 49),
        RiskLevel.HIGH: (50, 74),
        RiskLevel.CRITICAL: (75, 100),
    }

    def __init__(self):
        self.signal_cache = {}

    def calculate_score(
        self,
        detected_signals: List[str],
        additional_data: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Calculate comprehensive risk score.

        Args:
            detected_signals: List of signal codes detected
            additional_data: Additional context for scoring

        Returns:
            RiskAssessment with complete analysis
        """
        additional_data = additional_data or {}

        # Collect active signals
        active_signals = []
        total_weight = 0
        breakdown = {
            'critical': {'count': 0, 'weight': 0, 'signals': []},
            'high': {'count': 0, 'weight': 0, 'signals': []},
            'moderate': {'count': 0, 'weight': 0, 'signals': []},
            'low': {'count': 0, 'weight': 0, 'signals': []},
            'positive': {'count': 0, 'weight': 0, 'signals': []},
        }

        for signal_code in detected_signals:
            if signal_code in self.SIGNALS:
                signal = self.SIGNALS[signal_code]
                active_signals.append(signal)
                total_weight += signal.weight

                category = signal.category.value
                breakdown[category]['count'] += 1
                breakdown[category]['weight'] += signal.weight
                breakdown[category]['signals'].append(signal_code)

        # Apply modifiers from additional data
        if additional_data:
            total_weight = self._apply_modifiers(total_weight, additional_data)

        # Clamp score to 0-100
        score = max(0, min(100, total_weight))

        # Determine risk level
        level = self._get_risk_level(score)

        # Generate verdict
        verdict = level.value

        # Generate explanation
        explanation = self._generate_explanation(active_signals, score, level)

        # Generate recommended action
        recommended_action = self._generate_recommendation(level, active_signals)

        # Calculate confidence
        confidence = self._calculate_confidence(active_signals, additional_data)

        return RiskAssessment(
            score=score,
            level=level,
            verdict=verdict,
            signals=active_signals,
            explanation=explanation,
            recommended_action=recommended_action,
            confidence=confidence,
            breakdown=breakdown
        )

    def _apply_modifiers(self, base_score: int, data: Dict[str, Any]) -> int:
        """Apply score modifiers based on additional data."""
        score = base_score

        # AI confidence modifier
        ai_confidence = data.get('ai_confidence', 0)
        if ai_confidence > 0.9:
            score = int(score * 1.2)  # High AI confidence increases score
        elif ai_confidence < 0.3:
            score = int(score * 0.8)  # Low AI confidence decreases score

        # Threat intel match modifier
        if data.get('threat_intel_match'):
            score += 25

        # Multiple sources confirm modifier
        confirm_count = data.get('source_confirmations', 0)
        if confirm_count >= 3:
            score = int(score * 1.3)
        elif confirm_count >= 2:
            score = int(score * 1.15)

        # Recency modifier (recent reports increase score)
        if data.get('recent_reports', 0) > 5:
            score += 10

        return score

    def _get_risk_level(self, score: int) -> RiskLevel:
        """Determine risk level from score."""
        for level, (low, high) in self.THRESHOLDS.items():
            if low <= score <= high:
                return level
        return RiskLevel.CRITICAL if score > 100 else RiskLevel.LOW

    def _generate_explanation(
        self,
        signals: List[Signal],
        score: int,
        level: RiskLevel
    ) -> str:
        """Generate human-readable explanation."""
        if not signals:
            return "No significant risk indicators detected. This appears to be safe."

        critical_signals = [s for s in signals if s.category == SignalCategory.CRITICAL]
        high_signals = [s for s in signals if s.category == SignalCategory.HIGH]

        if critical_signals:
            primary = critical_signals[0]
            explanation = f"CRITICAL ALERT: {primary.description}. "
            if len(critical_signals) > 1:
                explanation += f"Additionally, {len(critical_signals) - 1} other critical indicators were detected. "
        elif high_signals:
            primary = high_signals[0]
            explanation = f"Warning: {primary.description}. "
            if len(high_signals) > 1:
                explanation += f"Multiple warning signs detected ({len(high_signals)} total). "
        else:
            moderate_signals = [s for s in signals if s.category == SignalCategory.MODERATE]
            if moderate_signals:
                explanation = f"Caution advised: {moderate_signals[0].description}. "
            else:
                explanation = "Minor concerns detected. "

        # Add score context
        if level == RiskLevel.CRITICAL:
            explanation += "This is almost certainly a scam attempt. Do not engage."
        elif level == RiskLevel.HIGH:
            explanation += "High probability of fraudulent activity. Exercise extreme caution."
        elif level == RiskLevel.MODERATE:
            explanation += "Some suspicious elements present. Verify independently before proceeding."
        else:
            explanation += "Risk level is low, but always remain vigilant."

        return explanation

    def _generate_recommendation(
        self,
        level: RiskLevel,
        signals: List[Signal]
    ) -> str:
        """Generate recommended action based on risk level."""
        recommendations = {
            RiskLevel.CRITICAL: [
                "Do not respond to this message or click any links",
                "Do not provide any personal or financial information",
                "Block the sender/caller immediately",
                "Report this to relevant authorities",
                "If you've shared any information, contact your bank immediately"
            ],
            RiskLevel.HIGH: [
                "Do not engage with the sender without verification",
                "Do not click on any links or download attachments",
                "Verify the sender through official channels",
                "Never send money or personal information",
                "Report suspicious activity"
            ],
            RiskLevel.MODERATE: [
                "Proceed with caution",
                "Verify the sender's identity through independent means",
                "Do not share sensitive information until verified",
                "Look up official contact information separately"
            ],
            RiskLevel.LOW: [
                "This appears to be low risk",
                "Standard precautions are recommended",
                "Verify sender if requesting any action",
                "Trust your instincts if something feels off"
            ],
        }

        return " ".join(recommendations.get(level, recommendations[RiskLevel.LOW])[:3])

    def _calculate_confidence(
        self,
        signals: List[Signal],
        data: Dict[str, Any]
    ) -> float:
        """Calculate confidence in the assessment."""
        base_confidence = 0.5

        # More signals = higher confidence
        signal_count = len(signals)
        if signal_count >= 5:
            base_confidence += 0.3
        elif signal_count >= 3:
            base_confidence += 0.2
        elif signal_count >= 1:
            base_confidence += 0.1

        # Critical signals increase confidence
        critical_count = len([s for s in signals if s.category == SignalCategory.CRITICAL])
        base_confidence += critical_count * 0.1

        # External validation increases confidence
        if data.get('threat_intel_match'):
            base_confidence += 0.15

        if data.get('ai_analysis_complete'):
            base_confidence += 0.1

        return min(0.99, base_confidence)

    def get_signal_info(self, signal_code: str) -> Optional[Signal]:
        """Get information about a specific signal."""
        return self.SIGNALS.get(signal_code)

    def list_signals_by_category(self, category: SignalCategory) -> List[Signal]:
        """List all signals in a category."""
        return [s for s in self.SIGNALS.values() if s.category == category]


class ThreatClassifier:
    """
    Classify threats into specific categories based on signals.
    """

    THREAT_MAPPINGS = {
        # Traditional scam types
        'PHISHING_URL': ['phishing_confirmed', 'suspicious_url', 'malware_detected', 'openphish_detected'],
        'BVN_PHISHING': ['bvn_phishing'],
        'NIN_PHISHING': ['nin_phishing'],
        'BANK_IMPERSONATION': ['account_threat', 'password_request', 'card_request'],
        'LOTTERY_SCAM': ['prize_claim'],
        'ADVANCE_FEE': ['inheritance_scam', 'wire_transfer_request'],
        'ROMANCE_SCAM': ['image_found_elsewhere', 'profile_inconsistencies', 'romance_scam'],
        'JOB_SCAM': [],  # Detected through pattern matching
        'INVESTMENT_SCAM': ['pig_butchering_scam'],
        'IMPERSONATION': ['ai_generated_image', 'image_found_elsewhere'],
        'GOVERNMENT_SCAM': [],
        'CATFISH': ['ai_generated_image', 'image_found_elsewhere', 'profile_inconsistencies'],

        # Modern scam types (2023-2024 emerging threats)
        'PIG_BUTCHERING': ['pig_butchering_scam', 'crypto_scam', 'romance_scam'],
        'SEXTORTION': ['sextortion_attempt'],
        'QUISHING': ['qr_code_phishing', 'suspicious_qr_code'],
        'MFA_BYPASS': ['mfa_bypass_attempt'],
        'CRYPTO_SCAM': ['crypto_scam', 'crypto_wallet_detected', 'crypto_scam_db_match'],
        'AI_PHISHING': ['ai_generated_phishing', 'high_manipulation'],
        'BLOCKLISTED': ['spamhaus_blocklisted', 'blocklisted_domain'],
    }

    @classmethod
    def classify(cls, detected_signals: List[str]) -> Tuple[str, float]:
        """
        Classify the primary threat type.

        Returns:
            Tuple of (threat_type, confidence)
        """
        best_match = 'LIKELY_SAFE'
        best_score = 0

        for threat_type, signal_codes in cls.THREAT_MAPPINGS.items():
            if not signal_codes:
                continue

            match_count = len(set(detected_signals) & set(signal_codes))
            if match_count > best_score:
                best_score = match_count
                best_match = threat_type

        confidence = min(0.95, 0.5 + (best_score * 0.15))

        return (best_match, confidence) if best_score > 0 else ('LIKELY_SAFE', 0.3)
