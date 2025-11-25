"""
Modern Scam Pattern Detection.

Specialized detection for modern scam types including:
- AI-powered phishing
- Quishing (QR code phishing)
- Pig butchering scams
- Sextortion
- MFA bypass attacks
- Deepfake-related scams
"""

import re
import logging
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('scamlytic.algorithms.modern_scams')


@dataclass
class ModernScamResult:
    """Result of modern scam detection."""
    scam_type: str
    confidence: float
    indicators: List[str]
    explanation: str
    risk_level: str  # low, medium, high, critical


class ModernScamDetector:
    """
    Detection engine for modern, sophisticated scam types.
    """

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all detection patterns."""
        self._compile_pig_butchering_patterns()
        self._compile_sextortion_patterns()
        self._compile_quishing_patterns()
        self._compile_mfa_bypass_patterns()
        self._compile_crypto_scam_patterns()
        self._compile_ai_phishing_patterns()
        self._compile_romance_scam_patterns()

    def _compile_pig_butchering_patterns(self):
        """Patterns for pig butchering (Sha Zhu Pan) scams."""
        self.pig_butchering_patterns = [
            # Investment platform lures
            re.compile(r'\b(?:trading\s+platform|investment\s+app|forex\s+trading)\b', re.I),
            re.compile(r'\b(?:guaranteed|sure|risk[\s-]?free)\s+(?:returns?|profits?|gains?)\b', re.I),
            re.compile(r'\b(?:100|200|300|500)\s*%\s+(?:return|profit|roi)\b', re.I),
            re.compile(r'\bwithdraw(?:al)?\s+(?:your\s+)?(?:profits?|earnings?|money)\b', re.I),

            # Relationship building
            re.compile(r'\b(?:invest\s+together|trade\s+with\s+me|show\s+you\s+how)\b', re.I),
            re.compile(r'\b(?:financial\s+freedom|passive\s+income|retire\s+early)\b', re.I),
            re.compile(r'\bmy\s+(?:uncle|friend|mentor|teacher)\s+(?:taught|showed)\b', re.I),

            # Crypto-specific
            re.compile(r'\b(?:usdt|binance|coinbase|metamask)\s+(?:wallet|account)\b', re.I),
            re.compile(r'\b(?:defi|liquidity\s+mining|yield\s+farming)\b', re.I),
            re.compile(r'\b(?:minimum|initial)\s+(?:deposit|investment)\s+(?:of\s+)?\$?\d+', re.I),
        ]

    def _compile_sextortion_patterns(self):
        """Patterns for sextortion scams."""
        self.sextortion_patterns = [
            # Threats
            re.compile(r'\bi\s+(?:have|got)\s+(?:your|the)\s+(?:video|recording|footage)\b', re.I),
            re.compile(r'\b(?:webcam|camera)\s+(?:was\s+)?(?:hacked|compromised|recording)\b', re.I),
            re.compile(r'\b(?:intimate|explicit|compromising)\s+(?:video|images?|photos?|content)\b', re.I),
            re.compile(r'\bsend\s+(?:to\s+)?(?:your\s+)?contacts?\b', re.I),
            re.compile(r'\b(?:share|post|upload)\s+(?:online|publicly|on\s+social)\b', re.I),

            # Payment demands
            re.compile(r'\bpay(?:ment)?\s+(?:in\s+)?(?:bitcoin|btc|crypto)\b', re.I),
            re.compile(r'\b(?:\$|usd\s*)?\d{3,5}\s+(?:in\s+)?(?:bitcoin|btc|cryptocurrency)\b', re.I),
            re.compile(r'\b(?:24|48|72)\s+hours?\s+(?:to\s+)?pay\b', re.I),
            re.compile(r'\bbitcoin\s+(?:wallet|address)\s*[:\s]+[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', re.I),

            # Claiming access
            re.compile(r'\b(?:trojan|malware|rat)\s+(?:on|in)\s+(?:your\s+)?(?:device|computer)\b', re.I),
            re.compile(r'\bi\s+(?:know|have)\s+your\s+password\b', re.I),
            re.compile(r'\bpassword\s+(?:is|was)\s*[:\s]+\S+\b', re.I),
        ]

    def _compile_quishing_patterns(self):
        """Patterns for QR code phishing (Quishing)."""
        self.quishing_patterns = [
            # QR code references
            re.compile(r'\bscan\s+(?:the\s+)?(?:qr|this)\s+code\b', re.I),
            re.compile(r'\b(?:qr|quick\s+response)\s+code\s+(?:to|for)\b', re.I),

            # Urgency with QR
            re.compile(r'\bscan\s+(?:now|immediately|quickly)\b', re.I),
            re.compile(r'\b(?:scan|use)\s+(?:this\s+)?code\s+(?:before|within)\b', re.I),

            # Common quishing contexts
            re.compile(r'\b(?:parking|meter|ticket)\s+(?:payment|fine)\b', re.I),
            re.compile(r'\b(?:package|delivery)\s+(?:confirmation|verification)\b', re.I),
            re.compile(r'\bmenu\s+(?:qr|code)\b', re.I),
            re.compile(r'\b(?:wifi|wi-fi)\s+(?:qr|code|connect)\b', re.I),
        ]

    def _compile_mfa_bypass_patterns(self):
        """Patterns for MFA bypass phishing attempts."""
        self.mfa_bypass_patterns = [
            # Authentication requests
            re.compile(r'\benter\s+(?:your\s+)?(?:verification|security|authentication)\s+code\b', re.I),
            re.compile(r'\b(?:2fa|mfa|two[\s-]?factor)\s+(?:code|token|verification)\b', re.I),
            re.compile(r'\b(?:one[\s-]?time|otp)\s+(?:code|password|token)\b', re.I),
            re.compile(r'\bsms\s+(?:code|verification)\b', re.I),

            # Session/token stealing
            re.compile(r'\bsession\s+(?:expired|timeout|invalid)\b', re.I),
            re.compile(r'\bre[\s-]?(?:authenticate|verify|login)\s+(?:your\s+)?(?:account|identity)\b', re.I),
            re.compile(r'\bunusual\s+(?:sign[\s-]?in|login|activity)\b', re.I),

            # Fake security alerts
            re.compile(r'\bsecurity\s+(?:alert|warning)\s*[:\-]\s+(?:verify|confirm)\b', re.I),
            re.compile(r'\bnew\s+device\s+(?:login|sign[\s-]?in|detected)\b', re.I),
        ]

    def _compile_crypto_scam_patterns(self):
        """Enhanced patterns for cryptocurrency scams."""
        self.crypto_scam_patterns = [
            # Fake giveaways
            re.compile(r'\b(?:elon|musk|bitcoin)\s+(?:giveaway|airdrop)\b', re.I),
            re.compile(r'\bsend\s+(?:\d+\s+)?(?:btc|eth|crypto)\s+(?:get|receive)\s+(?:\d+|double|triple)\b', re.I),
            re.compile(r'\b(?:double|triple|10x)\s+your\s+(?:btc|eth|crypto|bitcoin)\b', re.I),

            # Fake exchanges/platforms
            re.compile(r'\b(?:new|exclusive)\s+(?:trading|exchange)\s+platform\b', re.I),
            re.compile(r'\bregister\s+(?:now|today)\s+(?:get|receive|bonus)\b', re.I),

            # Recovery scams
            re.compile(r'\b(?:recover|retrieve)\s+(?:your\s+)?(?:lost|stolen)\s+(?:crypto|bitcoin|funds)\b', re.I),
            re.compile(r'\b(?:crypto|bitcoin)\s+recovery\s+(?:expert|service|specialist)\b', re.I),

            # NFT scams
            re.compile(r'\b(?:free|exclusive)\s+(?:nft|mint)\b', re.I),
            re.compile(r'\b(?:connect\s+wallet|wallet\s+connect)\s+(?:to\s+)?(?:claim|mint)\b', re.I),

            # Seed phrase fishing
            re.compile(r'\benter\s+(?:your\s+)?(?:seed|recovery)\s+phrase\b', re.I),
            re.compile(r'\b(?:12|24)\s+(?:word|words)\s+(?:seed|recovery|phrase)\b', re.I),
            re.compile(r'\b(?:private\s+key|seed\s+phrase)\s+(?:required|needed|enter)\b', re.I),
        ]

    def _compile_ai_phishing_patterns(self):
        """Patterns indicating AI-generated phishing content."""
        self.ai_phishing_patterns = [
            # Perfect but generic language
            re.compile(r'\bwe\s+(?:regret\s+to\s+)?inform\s+you\s+that\s+your\s+account\b', re.I),
            re.compile(r'\b(?:as\s+per|in\s+accordance\s+with)\s+(?:our|the)\s+(?:policy|terms)\b', re.I),

            # Unusual formality
            re.compile(r'\bkindly\s+(?:be\s+)?(?:informed|advised|note)\b', re.I),
            re.compile(r'\bfailure\s+to\s+comply\s+(?:will|may)\s+result\b', re.I),

            # AI-specific artifacts (when AI generates specific dates/numbers)
            re.compile(r'\bwithin\s+the\s+next\s+(?:\d+|twenty[\s-]?four)\s+hours?\b', re.I),
        ]

    def _compile_romance_scam_patterns(self):
        """Patterns for romance/dating scams."""
        self.romance_scam_patterns = [
            # Quick declarations
            re.compile(r'\b(?:i\s+)?(?:love|miss)\s+you\s+(?:so\s+much|already|deeply)\b', re.I),
            re.compile(r'\b(?:soul[\s-]?mate|destiny|meant\s+to\s+be)\b', re.I),
            re.compile(r'\b(?:god|fate)\s+(?:sent|brought)\s+(?:you|us)\b', re.I),

            # Financial requests
            re.compile(r'\b(?:stranded|stuck)\s+(?:in|at)\s+(?:\w+\s+)?(?:airport|hospital|abroad)\b', re.I),
            re.compile(r'\b(?:medical|hospital|emergency)\s+(?:bills?|expenses?|surgery)\b', re.I),
            re.compile(r'\bsend\s+(?:me\s+)?(?:money|funds)\s+(?:for|to|via)\b', re.I),
            re.compile(r'\b(?:wire|transfer)\s+(?:money|funds)\s+(?:to|via)\b', re.I),

            # Avoiding meeting
            re.compile(r'\bcamera\s+(?:is\s+)?(?:broken|not\s+working)\b', re.I),
            re.compile(r'\b(?:can\'t|cannot)\s+(?:video\s+)?call\b', re.I),

            # Military/overseas claims
            re.compile(r'\b(?:deployed|stationed)\s+(?:in|overseas|abroad)\b', re.I),
            re.compile(r'\b(?:military|army|navy)\s+(?:base|mission|duty)\b', re.I),
            re.compile(r'\b(?:oil\s+rig|offshore|peacekeeping)\b', re.I),
        ]

    def detect(self, text: str) -> List[ModernScamResult]:
        """
        Detect all modern scam types in the given text.

        Args:
            text: Text content to analyze

        Returns:
            List of detected scam types with confidence scores
        """
        results = []

        # Check each scam type
        scam_checks = [
            ('PIG_BUTCHERING', self.pig_butchering_patterns, self._explain_pig_butchering),
            ('SEXTORTION', self.sextortion_patterns, self._explain_sextortion),
            ('QUISHING', self.quishing_patterns, self._explain_quishing),
            ('MFA_BYPASS', self.mfa_bypass_patterns, self._explain_mfa_bypass),
            ('CRYPTO_SCAM', self.crypto_scam_patterns, self._explain_crypto_scam),
            ('AI_PHISHING', self.ai_phishing_patterns, self._explain_ai_phishing),
            ('ROMANCE_SCAM', self.romance_scam_patterns, self._explain_romance_scam),
        ]

        for scam_type, patterns, explain_func in scam_checks:
            indicators = []
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    indicators.extend(matches)

            if indicators:
                confidence = min(0.95, 0.3 + (len(indicators) * 0.15))
                risk_level = self._get_risk_level(confidence)

                results.append(ModernScamResult(
                    scam_type=scam_type,
                    confidence=confidence,
                    indicators=list(set(indicators))[:10],
                    explanation=explain_func(indicators),
                    risk_level=risk_level
                ))

        return results

    def _get_risk_level(self, confidence: float) -> str:
        """Convert confidence to risk level."""
        if confidence >= 0.8:
            return 'critical'
        elif confidence >= 0.6:
            return 'high'
        elif confidence >= 0.4:
            return 'medium'
        return 'low'

    def _explain_pig_butchering(self, indicators: List[str]) -> str:
        return (
            "This message shows signs of a 'Pig Butchering' scam - a sophisticated "
            "long-term fraud where scammers build relationships before convincing "
            "victims to invest in fake trading platforms. Never invest through "
            "platforms recommended by online acquaintances."
        )

    def _explain_sextortion(self, indicators: List[str]) -> str:
        return (
            "This appears to be a sextortion scam. Scammers falsely claim to have "
            "compromising content and demand cryptocurrency payment. These threats "
            "are almost always fake. Do not pay and do not respond."
        )

    def _explain_quishing(self, indicators: List[str]) -> str:
        return (
            "This message may involve QR code phishing (Quishing). Scanning malicious "
            "QR codes can lead to fake websites that steal credentials. Only scan "
            "QR codes from trusted, verified sources."
        )

    def _explain_mfa_bypass(self, indicators: List[str]) -> str:
        return (
            "This appears to be an MFA bypass phishing attempt. Attackers try to "
            "steal your authentication codes in real-time to access your accounts. "
            "Never enter verification codes on pages you reached through links."
        )

    def _explain_crypto_scam(self, indicators: List[str]) -> str:
        return (
            "This message contains cryptocurrency scam indicators. Never send crypto "
            "expecting to receive more back. Never enter seed phrases or private keys "
            "on any website. Legitimate platforms never ask for these."
        )

    def _explain_ai_phishing(self, indicators: List[str]) -> str:
        return (
            "This message shows characteristics of AI-generated phishing. Modern "
            "phishing uses AI to create convincing, error-free messages. Always verify "
            "requests through official channels, not links in messages."
        )

    def _explain_romance_scam(self, indicators: List[str]) -> str:
        return (
            "This message shows signs of a romance scam. Scammers create fake "
            "relationships and eventually request money for emergencies. Never send "
            "money to someone you haven't met in person."
        )

    def detect_crypto_wallet(self, text: str) -> List[Dict[str, Any]]:
        """Extract and analyze cryptocurrency wallet addresses."""
        wallets = []

        # Bitcoin
        btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        for match in btc_pattern.finditer(text):
            wallets.append({
                'type': 'bitcoin',
                'address': match.group(),
                'position': match.start()
            })

        # Ethereum
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
        for match in eth_pattern.finditer(text):
            wallets.append({
                'type': 'ethereum',
                'address': match.group(),
                'position': match.start()
            })

        return wallets

    def detect_qr_code_context(self, text: str) -> Dict[str, Any]:
        """Analyze context around QR code mentions."""
        result = {
            'mentions_qr': False,
            'is_suspicious': False,
            'context': '',
            'risk_factors': []
        }

        qr_mentions = re.findall(
            r'.{0,50}(?:qr|quick\s+response)\s+code.{0,50}',
            text,
            re.I
        )

        if qr_mentions:
            result['mentions_qr'] = True
            result['context'] = qr_mentions[0]

            # Check for suspicious contexts
            suspicious_contexts = [
                'payment', 'verify', 'confirm', 'login', 'sign in',
                'urgent', 'immediately', 'expired', 'update'
            ]

            for context in suspicious_contexts:
                if context in text.lower():
                    result['risk_factors'].append(context)

            result['is_suspicious'] = len(result['risk_factors']) >= 2

        return result
