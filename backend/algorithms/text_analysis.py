"""
Advanced Text Analysis Module.

NLP-based analysis for detecting scam patterns, sentiment,
urgency, and manipulation tactics in text.
"""

import re
import logging
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import Counter

logger = logging.getLogger('scamlytic.algorithms.text')


@dataclass
class TextAnalysisResult:
    """Result of text analysis."""
    language: str = 'en'
    word_count: int = 0
    sentence_count: int = 0
    urgency_score: float = 0.0
    manipulation_score: float = 0.0
    sentiment_score: float = 0.0  # -1 to 1
    formality_score: float = 0.5
    grammar_score: float = 1.0
    urls_found: List[str] = field(default_factory=list)
    emails_found: List[str] = field(default_factory=list)
    phones_found: List[str] = field(default_factory=list)
    numbers_found: List[str] = field(default_factory=list)
    key_phrases: List[str] = field(default_factory=list)
    suspicious_phrases: List[str] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)


class TextAnalyzer:
    """
    Advanced text analysis for scam detection.
    """

    # Urgency indicators
    URGENCY_PHRASES = [
        r'\burgent(?:ly)?\b',
        r'\bimmediately\b',
        r'\bright\s+now\b',
        r'\basap\b',
        r'\b(?:act|respond|reply)\s+(?:fast|quick(?:ly)?|now|immediately)\b',
        r'\blimited\s+time\b',
        r'\bexpir(?:e|es|ed|ing)\b',
        r'\b(?:only|just)\s+\d+\s+(?:hour|day|minute)s?\s+left\b',
        r'\bdeadline\b',
        r'\blast\s+chance\b',
        r'\bdon\'?t\s+(?:miss|delay|wait)\b',
        r'\btime\s+(?:is\s+)?running\s+out\b',
        r'\bwithin\s+(?:24|48|72)\s+hours?\b',
        r'\btoday\s+only\b',
        r'\bends?\s+(?:soon|today|tonight)\b',
    ]

    # Authority/impersonation indicators
    AUTHORITY_PHRASES = [
        r'\b(?:bank|financial\s+institution)\b',
        r'\b(?:government|federal|state)\s+(?:agency|department|office)\b',
        r'\b(?:irs|fbi|cia|dhs|sec)\b',
        r'\b(?:police|sheriff|law\s+enforcement)\b',
        r'\b(?:technical?|customer|it)\s+support\b',
        r'\b(?:microsoft|apple|google|amazon|paypal|netflix)\b',
        r'\bofficial\s+(?:notice|communication|letter)\b',
        r'\byour\s+account\s+(?:has\s+been|is|will\s+be)\b',
        r'\bsecurity\s+(?:alert|warning|notice|department)\b',
        r'\bverif(?:y|ication)\s+(?:your|required|needed)\b',
        r'\bsuspicious\s+activity\b',
        r'\bunauthorized\s+(?:access|login|transaction)\b',
    ]

    # Financial scam indicators
    FINANCIAL_PHRASES = [
        r'\b(?:wire|bank)\s+transfer\b',
        r'\bgift\s+cards?\b',
        r'\b(?:bit)?coin\b',
        r'\bcryptocurrency\b',
        r'\binvestment\s+opportunit(?:y|ies)\b',
        r'\bguaranteed\s+(?:return|profit|income)\b',
        r'\b(?:double|triple)\s+your\s+money\b',
        r'\b(?:won|win|winner)\s+(?:a|the)?\s*(?:\$|usd|euro|pound|prize|lottery)\b',
        r'\binheritance\b',
        r'\b(?:million|billion|thousand)\s+(?:dollar|usd|euro|pound)s?\b',
        r'\bfree\s+money\b',
        r'\bunclaimed\s+(?:funds|money|prize)\b',
        r'\bprocessing\s+fee\b',
        r'\badvance\s+(?:fee|payment)\b',
        r'\bwestern\s+union\b',
        r'\bmoneygram\b',
    ]

    # Personal info request indicators
    INFO_REQUEST_PHRASES = [
        r'\b(?:social\s+security|ssn)\s*(?:number)?\b',
        r'\bpassword\b',
        r'\b(?:credit|debit)\s+card\b',
        r'\bbank\s+(?:account|details|information)\b',
        r'\bpin\s*(?:number|code)?\b',
        r'\b(?:bvn|bank\s+verification)\b',  # Nigerian specific
        r'\b(?:nin|national\s+id(?:entity)?)\b',  # Nigerian specific
        r'\bdate\s+of\s+birth\b',
        r'\bmother\'?s?\s+maiden\s+name\b',
        r'\bsecurity\s+(?:question|answer)\b',
        r'\b(?:confirm|verify|update)\s+(?:your\s+)?(?:details|information|identity)\b',
        r'\bclick\s+(?:here|this\s+link|below)\b',
        r'\blogin\s+(?:here|credentials)\b',
    ]

    # Threat/fear indicators
    THREAT_PHRASES = [
        r'\baccount\s+(?:will\s+be\s+)?(?:suspend|close|block|terminat)(?:ed|ion)?\b',
        r'\blegal\s+(?:action|proceedings)\b',
        r'\barrest(?:ed)?\s+warrant\b',
        r'\bprosecute(?:d|ion)?\b',
        r'\bimprison(?:ment|ed)?\b',
        r'\bfine(?:d|s)?\b',
        r'\bpenalt(?:y|ies)\b',
        r'\bseize\s+(?:your\s+)?(?:assets|property)\b',
        r'\breport(?:ed)?\s+to\s+(?:authorities|police)\b',
        r'\bconsequences\b',
        r'\bfailure\s+to\s+(?:comply|respond)\b',
    ]

    # Too good to be true indicators
    TGTBT_PHRASES = [
        r'\bfree\b',
        r'\bno\s+(?:cost|fee|charge|obligation|risk)\b',
        r'\brisk[\s-]?free\b',
        r'\b100\s*%\s+(?:guaranteed|safe|secure)\b',
        r'\beasy\s+money\b',
        r'\bwork\s+from\s+home\b',
        r'\b(?:make|earn)\s+\$?\d+[k,]?\d*\s+(?:per|a)\s+(?:day|week|month|hour)\b',
        r'\bget\s+rich\s+(?:quick|fast)\b',
        r'\bsecret\s+(?:method|formula|system)\b',
        r'\bexclusive\s+(?:offer|deal|opportunity)\b',
        r'\bselected\s+(?:winner|recipient|candidate)\b',
        r'\bcongratulations?\b',
    ]

    # Grammar/style issues common in scams
    GRAMMAR_ISSUES = [
        r'\b(kindly|do the needful|revert back)\b',
        r'\bdear\s+(?:friend|customer|user|sir|madam|beneficiary)\b',
        r'\battn:?\s*[a-z]+\b',
        r'\bfrom\s+the\s+desk\s+of\b',
        r'\bthis\s+is\s+to\s+inform\s+you\b',
        r'\bwe\s+wish\s+to\s+(?:notify|inform)\b',
        r'\byour\s+email\s+(?:address\s+)?(?:has\s+been\s+)?(?:selected|chosen)\b',
    ]

    # URL patterns
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+|'
        r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?',
        re.IGNORECASE
    )

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    )

    # Phone pattern (international)
    PHONE_PATTERN = re.compile(
        r'(?:\+\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        re.IGNORECASE
    )

    # Money/currency pattern
    MONEY_PATTERN = re.compile(
        r'(?:[$€£¥₦]|USD|EUR|GBP|NGN)\s*\d+(?:,\d{3})*(?:\.\d{2})?|'
        r'\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:dollars?|euros?|pounds?|naira)',
        re.IGNORECASE
    )

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for efficiency."""
        self.urgency_patterns = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_PHRASES]
        self.authority_patterns = [re.compile(p, re.IGNORECASE) for p in self.AUTHORITY_PHRASES]
        self.financial_patterns = [re.compile(p, re.IGNORECASE) for p in self.FINANCIAL_PHRASES]
        self.info_request_patterns = [re.compile(p, re.IGNORECASE) for p in self.INFO_REQUEST_PHRASES]
        self.threat_patterns = [re.compile(p, re.IGNORECASE) for p in self.THREAT_PHRASES]
        self.tgtbt_patterns = [re.compile(p, re.IGNORECASE) for p in self.TGTBT_PHRASES]
        self.grammar_patterns = [re.compile(p, re.IGNORECASE) for p in self.GRAMMAR_ISSUES]

    def analyze(self, text: str) -> TextAnalysisResult:
        """
        Perform comprehensive text analysis.

        Args:
            text: The text to analyze

        Returns:
            TextAnalysisResult with all analysis metrics
        """
        result = TextAnalysisResult()

        if not text or not text.strip():
            return result

        # Basic stats
        result.word_count = len(text.split())
        result.sentence_count = len(re.split(r'[.!?]+', text))

        # Extract entities
        result.urls_found = self._extract_urls(text)
        result.emails_found = self._extract_emails(text)
        result.phones_found = self._extract_phones(text)
        result.numbers_found = self._extract_money(text)

        # Calculate scores
        result.urgency_score = self._calculate_urgency_score(text)
        result.manipulation_score = self._calculate_manipulation_score(text)
        result.sentiment_score = self._calculate_sentiment_score(text)
        result.grammar_score = self._calculate_grammar_score(text)

        # Extract suspicious phrases
        result.suspicious_phrases = self._extract_suspicious_phrases(text)
        result.key_phrases = self._extract_key_phrases(text)

        # Detect language
        result.language = self._detect_language(text)

        return result

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        urls = self.URL_PATTERN.findall(text)
        return list(set(urls))[:10]  # Limit to 10 unique URLs

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        emails = self.EMAIL_PATTERN.findall(text)
        return list(set(emails))[:5]

    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers from text."""
        phones = self.PHONE_PATTERN.findall(text)
        # Filter out short matches that are likely not phone numbers
        phones = [p for p in phones if len(re.sub(r'\D', '', p)) >= 7]
        return list(set(phones))[:5]

    def _extract_money(self, text: str) -> List[str]:
        """Extract monetary values from text."""
        amounts = self.MONEY_PATTERN.findall(text)
        return list(set(amounts))[:5]

    def _calculate_urgency_score(self, text: str) -> float:
        """Calculate urgency score (0-1)."""
        matches = 0
        for pattern in self.urgency_patterns:
            matches += len(pattern.findall(text))

        # Normalize: 0 matches = 0, 5+ matches = 1
        return min(1.0, matches / 5.0)

    def _calculate_manipulation_score(self, text: str) -> float:
        """Calculate manipulation/social engineering score (0-1)."""
        scores = []

        # Authority score
        authority_matches = sum(len(p.findall(text)) for p in self.authority_patterns)
        scores.append(min(1.0, authority_matches / 3.0))

        # Financial score
        financial_matches = sum(len(p.findall(text)) for p in self.financial_patterns)
        scores.append(min(1.0, financial_matches / 3.0))

        # Info request score
        info_matches = sum(len(p.findall(text)) for p in self.info_request_patterns)
        scores.append(min(1.0, info_matches / 2.0))

        # Threat score
        threat_matches = sum(len(p.findall(text)) for p in self.threat_patterns)
        scores.append(min(1.0, threat_matches / 2.0))

        # TGTBT score
        tgtbt_matches = sum(len(p.findall(text)) for p in self.tgtbt_patterns)
        scores.append(min(1.0, tgtbt_matches / 3.0))

        # Weighted average
        weights = [0.2, 0.25, 0.25, 0.15, 0.15]
        return sum(s * w for s, w in zip(scores, weights))

    def _calculate_sentiment_score(self, text: str) -> float:
        """
        Calculate sentiment score (-1 to 1).
        Negative = threatening/fearful, Positive = promising/exciting
        """
        # Simple lexicon-based approach
        positive_words = [
            'congratulations', 'winner', 'won', 'prize', 'free', 'bonus',
            'reward', 'lucky', 'selected', 'special', 'exclusive', 'opportunity',
            'guaranteed', 'secure', 'safe', 'easy', 'simple'
        ]
        negative_words = [
            'suspend', 'terminate', 'block', 'arrest', 'legal', 'prosecute',
            'urgent', 'immediately', 'warning', 'alert', 'expire', 'deadline',
            'penalty', 'fine', 'seize', 'fraud', 'suspicious', 'unauthorized'
        ]

        text_lower = text.lower()
        pos_count = sum(1 for word in positive_words if word in text_lower)
        neg_count = sum(1 for word in negative_words if word in text_lower)

        total = pos_count + neg_count
        if total == 0:
            return 0.0

        return (pos_count - neg_count) / total

    def _calculate_grammar_score(self, text: str) -> float:
        """
        Calculate grammar quality score (0-1).
        Lower score = more grammar issues typical of scams
        """
        issues = sum(len(p.findall(text)) for p in self.grammar_patterns)

        # Check for ALL CAPS sections
        caps_words = len(re.findall(r'\b[A-Z]{4,}\b', text))
        issues += caps_words * 0.5

        # Check for excessive punctuation
        excessive_punct = len(re.findall(r'[!?]{2,}', text))
        issues += excessive_punct

        # Normalize: 0 issues = 1, 5+ issues = 0
        return max(0.0, 1.0 - (issues / 5.0))

    def _extract_suspicious_phrases(self, text: str) -> List[str]:
        """Extract suspicious phrases found in text."""
        suspicious = []

        all_patterns = (
            self.urgency_patterns +
            self.authority_patterns +
            self.financial_patterns +
            self.info_request_patterns +
            self.threat_patterns +
            self.tgtbt_patterns
        )

        for pattern in all_patterns:
            matches = pattern.findall(text)
            suspicious.extend(matches)

        return list(set(suspicious))[:20]

    def _extract_key_phrases(self, text: str) -> List[str]:
        """Extract key phrases from text using simple n-gram extraction."""
        # Simple bigram and trigram extraction
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())

        bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words)-1)]
        trigrams = [f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words)-2)]

        # Count frequencies
        phrase_counts = Counter(bigrams + trigrams)

        # Return most common (excluding very common phrases)
        common_phrases = ['the', 'to', 'and', 'a', 'of', 'in', 'is', 'it', 'you', 'that']
        key_phrases = [
            phrase for phrase, count in phrase_counts.most_common(10)
            if not all(word in common_phrases for word in phrase.split())
        ]

        return key_phrases[:5]

    def _detect_language(self, text: str) -> str:
        """Detect language of text."""
        try:
            from langdetect import detect
            return detect(text)
        except Exception:
            return 'en'  # Default to English


class ScamPatternAnalyzer:
    """
    Specific scam pattern detection and classification.
    """

    # Nigerian-specific patterns
    NIGERIAN_PATTERNS = {
        'bvn_phishing': [
            r'\bbvn\b',
            r'\bbank\s+verification\s+number\b',
            r'\bverify\s+(?:your\s+)?bvn\b',
            r'\bbvn\s+(?:update|verification|linking)\b',
        ],
        'nin_phishing': [
            r'\bnin\b',
            r'\bnational\s+id(?:entity)?\s+number\b',
            r'\bverify\s+(?:your\s+)?nin\b',
            r'\bnin\s+(?:update|verification|linking)\b',
        ],
        'bank_impersonation': [
            r'\b(?:gtbank|gt\s+bank|guaranty\s+trust)\b',
            r'\b(?:first\s+bank|firstbank)\b',
            r'\b(?:access\s+bank|accessbank)\b',
            r'\b(?:uba|united\s+bank\s+for\s+africa)\b',
            r'\b(?:zenith\s+bank|zenithbank)\b',
            r'\b(?:union\s+bank)\b',
            r'\b(?:sterling\s+bank)\b',
            r'\b(?:wema\s+bank)\b',
            r'\b(?:ecobank)\b',
            r'\b(?:fidelity\s+bank)\b',
            r'\b(?:stanbic\s+ibtc)\b',
            r'\b(?:polaris\s+bank)\b',
            r'\b(?:keystone\s+bank)\b',
        ],
    }

    # Universal scam patterns
    SCAM_PATTERNS = {
        'lottery_scam': [
            r'\b(?:won|winner|winning)\s+(?:a\s+)?(?:lottery|prize|sweepstakes)\b',
            r'\blotto\s+(?:winner|winning)\b',
            r'\b(?:claim|collect)\s+(?:your\s+)?(?:prize|winning|money)\b',
            r'\brandom(?:ly)?\s+selected\s+(?:winner|as)\b',
        ],
        'advance_fee': [
            r'\bprocessing\s+fee\b',
            r'\btransfer\s+fee\b',
            r'\bhandling\s+(?:fee|charge)\b',
            r'\bpay\s+(?:a\s+)?(?:small\s+)?(?:fee|amount)\s+(?:to|for)\b',
            r'\badvance\s+(?:fee|payment)\b',
        ],
        'romance_scam': [
            r'\bi\s+(?:love|miss)\s+you\b',
            r'\bsoul\s*mate\b',
            r'\bdestined\s+to\s+be\b',
            r'\bsend\s+(?:me\s+)?money\s+(?:for|to)\b',
            r'\bstranded\s+(?:in|at)\b',
            r'\bemergency\s+(?:need|require|situation)\b',
        ],
        'job_scam': [
            r'\b(?:work\s+from\s+home|wfh)\s+(?:job|opportunity)\b',
            r'\b(?:make|earn)\s+\$\d+\s+(?:per|a)\s+(?:day|hour|week)\b',
            r'\bno\s+(?:experience|skill)\s+(?:needed|required)\b',
            r'\bdata\s+entry\s+(?:job|work)\b',
            r'\bhiring\s+(?:immediately|now|urgently)\b',
        ],
        'investment_scam': [
            r'\bguaranteed\s+(?:return|profit|roi)\b',
            r'\b(?:double|triple)\s+your\s+(?:money|investment)\b',
            r'\b(?:high|huge)\s+(?:return|profit|roi)\b',
            r'\brisk[\s-]?free\s+investment\b',
            r'\bpassive\s+income\b',
        ],
        'crypto_scam': [
            r'\b(?:bitcoin|btc|ethereum|eth|crypto)\s+(?:investment|trading|opportunity)\b',
            r'\bforex\s+(?:trading|investment|opportunity)\b',
            r'\b(?:nft|defi)\s+(?:investment|opportunity)\b',
            r'\bwallet\s+(?:address|verification)\b',
            r'\b(?:seed|recovery)\s+phrase\b',
        ],
        'tech_support_scam': [
            r'\b(?:virus|malware)\s+(?:detected|found)\b',
            r'\b(?:computer|device)\s+(?:is\s+)?(?:infected|compromised)\b',
            r'\bcall\s+(?:this\s+number|us)\s+(?:immediately|now)\b',
            r'\btechnical?\s+support\b',
            r'\b(?:microsoft|apple|google)\s+(?:support|security)\b',
        ],
        'government_scam': [
            r'\b(?:irs|tax)\s+(?:refund|return|debt)\b',
            r'\b(?:government|federal)\s+(?:grant|assistance|loan)\b',
            r'\b(?:stimulus|relief)\s+(?:check|payment)\b',
            r'\b(?:social\s+security|ssa)\s+(?:suspension|fraud)\b',
            r'\b(?:court|legal)\s+(?:summons|notice)\b',
        ],
    }

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all patterns for efficiency."""
        self.compiled_nigerian = {}
        for category, patterns in self.NIGERIAN_PATTERNS.items():
            self.compiled_nigerian[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        self.compiled_scam = {}
        for category, patterns in self.SCAM_PATTERNS.items():
            self.compiled_scam[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def detect_patterns(self, text: str) -> Dict[str, Any]:
        """
        Detect scam patterns in text.

        Returns:
            Dictionary with detected patterns and their matches
        """
        results = {
            'nigerian_patterns': {},
            'scam_patterns': {},
            'detected_categories': [],
            'total_matches': 0
        }

        # Check Nigerian patterns
        for category, patterns in self.compiled_nigerian.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                matches.extend(found)
            if matches:
                results['nigerian_patterns'][category] = list(set(matches))
                results['detected_categories'].append(category)
                results['total_matches'] += len(matches)

        # Check universal scam patterns
        for category, patterns in self.compiled_scam.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                matches.extend(found)
            if matches:
                results['scam_patterns'][category] = list(set(matches))
                results['detected_categories'].append(category)
                results['total_matches'] += len(matches)

        return results

    def classify_threat(self, text: str, pattern_results: Dict[str, Any]) -> Tuple[str, float]:
        """
        Classify the primary threat type based on pattern matches.

        Returns:
            Tuple of (threat_type, confidence)
        """
        categories = pattern_results.get('detected_categories', [])

        if not categories:
            return ('LIKELY_SAFE', 0.1)

        # Priority order for classification
        priority = [
            'bvn_phishing',
            'nin_phishing',
            'bank_impersonation',
            'crypto_scam',
            'investment_scam',
            'lottery_scam',
            'advance_fee',
            'romance_scam',
            'job_scam',
            'tech_support_scam',
            'government_scam',
        ]

        # Map to threat types
        threat_map = {
            'bvn_phishing': 'BVN_PHISHING',
            'nin_phishing': 'NIN_PHISHING',
            'bank_impersonation': 'BANK_IMPERSONATION',
            'lottery_scam': 'LOTTERY_SCAM',
            'advance_fee': 'ADVANCE_FEE',
            'romance_scam': 'ROMANCE_SCAM',
            'job_scam': 'JOB_SCAM',
            'investment_scam': 'INVESTMENT_SCAM',
            'crypto_scam': 'CRYPTO_SCAM',
            'tech_support_scam': 'TECH_SUPPORT_SCAM',
            'government_scam': 'GOVERNMENT_SCAM',
        }

        # Find highest priority match
        for category in priority:
            if category in categories:
                confidence = min(0.95, 0.5 + (pattern_results['total_matches'] * 0.1))
                return (threat_map.get(category, 'LIKELY_SAFE'), confidence)

        return ('LIKELY_SAFE', 0.3)
