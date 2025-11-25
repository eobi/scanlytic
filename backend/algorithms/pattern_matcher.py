"""
Pattern Matcher Module.

Advanced pattern matching for scam detection using
multiple matching strategies.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from difflib import SequenceMatcher

logger = logging.getLogger('scamlytic.algorithms.pattern')


@dataclass
class PatternMatch:
    """A single pattern match result."""
    pattern_name: str
    pattern_type: str  # regex, keyword, fuzzy, semantic
    matched_text: str
    position: int
    confidence: float
    weight: int
    category: str


@dataclass
class PatternMatchResult:
    """Result of pattern matching."""
    matches: List[PatternMatch] = field(default_factory=list)
    total_weight: int = 0
    unique_patterns: int = 0
    categories_matched: Set[str] = field(default_factory=set)


class PatternMatcher:
    """
    Advanced pattern matching engine for scam detection.
    """

    def __init__(self):
        self.patterns = self._load_patterns()
        self._compile_patterns()

    def _load_patterns(self) -> Dict[str, Any]:
        """Load pattern definitions."""
        return {
            # Critical patterns (weight 30-40)
            'critical': {
                'bvn_request': {
                    'patterns': [
                        r'\bverify\s+(?:your\s+)?bvn\b',
                        r'\bbvn\s+(?:update|verification|linking)\b',
                        r'\benter\s+(?:your\s+)?bvn\b',
                        r'\bprovide\s+(?:your\s+)?bvn\b',
                    ],
                    'weight': 40,
                    'category': 'bvn_phishing',
                },
                'nin_request': {
                    'patterns': [
                        r'\bverify\s+(?:your\s+)?nin\b',
                        r'\bnin\s+(?:update|verification|linking)\b',
                        r'\benter\s+(?:your\s+)?nin\b',
                    ],
                    'weight': 40,
                    'category': 'nin_phishing',
                },
                'password_request': {
                    'patterns': [
                        r'\benter\s+(?:your\s+)?password\b',
                        r'\bverify\s+(?:your\s+)?password\b',
                        r'\bconfirm\s+(?:your\s+)?password\b',
                        r'\bpassword\s+(?:is\s+)?required\b',
                    ],
                    'weight': 35,
                    'category': 'phishing',
                },
                'card_request': {
                    'patterns': [
                        r'\b(?:credit|debit)\s+card\s+(?:number|details|info)\b',
                        r'\bcard\s+(?:cvv|cvc|expir)\b',
                        r'\benter\s+(?:your\s+)?card\b',
                    ],
                    'weight': 35,
                    'category': 'financial_phishing',
                },
            },

            # High severity patterns (weight 20-29)
            'high': {
                'account_threat': {
                    'patterns': [
                        r'\baccount\s+(?:will\s+be\s+)?(?:suspend|block|terminat|clos)(?:ed)?\b',
                        r'\b(?:suspend|block|terminat)(?:e|ed|ing)?\s+(?:your\s+)?account\b',
                    ],
                    'weight': 25,
                    'category': 'threat',
                },
                'urgency_extreme': {
                    'patterns': [
                        r'\bwithin\s+(?:24|48)\s+hours?\b',
                        r'\bimmediate(?:ly)?\s+action\s+required\b',
                        r'\bfailure\s+to\s+(?:comply|respond)\b',
                    ],
                    'weight': 25,
                    'category': 'urgency',
                },
                'prize_claim': {
                    'patterns': [
                        r'\bclaim\s+(?:your\s+)?(?:prize|winning|reward)\b',
                        r'\bwon\s+(?:a\s+)?(?:prize|lottery|sweepstakes)\b',
                    ],
                    'weight': 28,
                    'category': 'lottery_scam',
                },
                'money_promise': {
                    'patterns': [
                        r'\b(?:million|billion)\s+(?:dollar|usd|naira|euro|pound)s?\b',
                        r'\binheritance\s+(?:fund|money)\b',
                        r'\bunclaimed\s+(?:fund|money|asset)s?\b',
                    ],
                    'weight': 26,
                    'category': 'advance_fee',
                },
            },

            # Moderate severity patterns (weight 10-19)
            'moderate': {
                'shortened_url': {
                    'patterns': [
                        r'\bbit\.ly/\w+\b',
                        r'\btinyurl\.com/\w+\b',
                        r'\bgoo\.gl/\w+\b',
                        r'\bt\.co/\w+\b',
                        r'\bshort\.link/\w+\b',
                        r'\brebrand\.ly/\w+\b',
                    ],
                    'weight': 15,
                    'category': 'suspicious_url',
                },
                'click_bait': {
                    'patterns': [
                        r'\bclick\s+(?:here|this\s+link|below)\b',
                        r'\bfollow\s+(?:this\s+)?link\b',
                        r'\bopen\s+(?:the\s+)?attachment\b',
                    ],
                    'weight': 12,
                    'category': 'phishing',
                },
                'urgency_moderate': {
                    'patterns': [
                        r'\burgent(?:ly)?\b',
                        r'\blimited\s+time\b',
                        r'\bact\s+(?:fast|now|quick)\b',
                    ],
                    'weight': 15,
                    'category': 'urgency',
                },
                'wire_transfer': {
                    'patterns': [
                        r'\b(?:wire|bank)\s+transfer\b',
                        r'\bwestern\s+union\b',
                        r'\bmoneygram\b',
                    ],
                    'weight': 18,
                    'category': 'financial',
                },
                'gift_card': {
                    'patterns': [
                        r'\bgift\s+card\b',
                        r'\bitunes\s+card\b',
                        r'\bgoogle\s+play\s+card\b',
                        r'\bamazon\s+card\b',
                    ],
                    'weight': 18,
                    'category': 'financial',
                },
            },

            # Low severity patterns (weight 5-9)
            'low': {
                'generic_greeting': {
                    'patterns': [
                        r'\bdear\s+(?:customer|user|friend|valued|sir|madam)\b',
                        r'\battention\s+(?:customer|user|beneficiary)\b',
                    ],
                    'weight': 8,
                    'category': 'style',
                },
                'formal_opener': {
                    'patterns': [
                        r'\bthis\s+is\s+to\s+(?:inform|notify)\b',
                        r'\bwe\s+(?:wish|are\s+pleased)\s+to\s+(?:inform|notify)\b',
                        r'\bfrom\s+the\s+desk\s+of\b',
                    ],
                    'weight': 7,
                    'category': 'style',
                },
                'nigerian_english': {
                    'patterns': [
                        r'\bkindly\s+(?:do|provide|send|reply)\b',
                        r'\bdo\s+the\s+needful\b',
                        r'\brevert\s+back\b',
                    ],
                    'weight': 8,
                    'category': 'style',
                },
            }
        }

    def _compile_patterns(self):
        """Compile all regex patterns for efficiency."""
        self.compiled_patterns = {}
        for severity, categories in self.patterns.items():
            self.compiled_patterns[severity] = {}
            for name, config in categories.items():
                self.compiled_patterns[severity][name] = {
                    'patterns': [re.compile(p, re.IGNORECASE) for p in config['patterns']],
                    'weight': config['weight'],
                    'category': config['category'],
                }

    def match(self, text: str) -> PatternMatchResult:
        """
        Match text against all patterns.

        Args:
            text: Text to analyze

        Returns:
            PatternMatchResult with all matches
        """
        result = PatternMatchResult()
        seen_patterns = set()

        for severity, categories in self.compiled_patterns.items():
            for pattern_name, config in categories.items():
                for pattern in config['patterns']:
                    for match in pattern.finditer(text):
                        pm = PatternMatch(
                            pattern_name=pattern_name,
                            pattern_type='regex',
                            matched_text=match.group(),
                            position=match.start(),
                            confidence=0.9,
                            weight=config['weight'],
                            category=config['category']
                        )
                        result.matches.append(pm)
                        result.total_weight += config['weight']
                        result.categories_matched.add(config['category'])

                        if pattern_name not in seen_patterns:
                            seen_patterns.add(pattern_name)
                            result.unique_patterns += 1

        return result

    def match_fuzzy(self, text: str, target_phrases: List[str], threshold: float = 0.8) -> List[Dict[str, Any]]:
        """
        Fuzzy match text against target phrases.

        Args:
            text: Text to analyze
            target_phrases: Phrases to match against
            threshold: Minimum similarity threshold (0-1)

        Returns:
            List of fuzzy matches
        """
        matches = []
        words = text.lower().split()

        # Create n-grams for matching
        for n in range(2, 5):  # 2-4 word phrases
            for i in range(len(words) - n + 1):
                phrase = ' '.join(words[i:i+n])
                for target in target_phrases:
                    similarity = SequenceMatcher(None, phrase, target.lower()).ratio()
                    if similarity >= threshold:
                        matches.append({
                            'matched_phrase': phrase,
                            'target_phrase': target,
                            'similarity': similarity,
                            'position': i
                        })

        return matches

    def get_pattern_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get pattern configuration by name."""
        for severity, categories in self.patterns.items():
            if name in categories:
                return {
                    'severity': severity,
                    **categories[name]
                }
        return None

    def add_custom_pattern(
        self,
        name: str,
        patterns: List[str],
        weight: int,
        category: str,
        severity: str = 'moderate'
    ):
        """Add a custom pattern at runtime."""
        if severity not in self.patterns:
            severity = 'moderate'

        self.patterns[severity][name] = {
            'patterns': patterns,
            'weight': weight,
            'category': category,
        }

        self.compiled_patterns[severity][name] = {
            'patterns': [re.compile(p, re.IGNORECASE) for p in patterns],
            'weight': weight,
            'category': category,
        }


class DomainPatternMatcher:
    """
    Pattern matching specifically for domains.
    """

    # Known legitimate domains (whitelist)
    LEGITIMATE_DOMAINS = {
        # Banks (Nigeria)
        'gtbank.com', 'firstbanknigeria.com', 'accessbankplc.com',
        'ubagroup.com', 'zenithbank.com', 'sterlingbankng.com',

        # Major platforms
        'google.com', 'facebook.com', 'instagram.com', 'twitter.com',
        'linkedin.com', 'youtube.com', 'amazon.com', 'apple.com',
        'microsoft.com', 'paypal.com', 'netflix.com', 'spotify.com',

        # Email providers
        'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
    }

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.xyz', '.top', '.click', '.loan', '.work',
        '.win', '.download', '.stream', '.racing', '.bid',
    }

    # Brand impersonation patterns
    BRAND_PATTERNS = {
        'google': r'g[o0][o0]gle|g00gle|go0gle',
        'facebook': r'faceb[o0][o0]k|facebo0k|facebok',
        'instagram': r'[i1]nstagram|1nstagram|instagran',
        'paypal': r'paypa[l1]|paypa1|pay-pal|paypai',
        'microsoft': r'm[i1]cr[o0]s[o0]ft|micr0soft|mircosoft',
        'amazon': r'amaz[o0]n|amazom|arnazon|arnazon',
        'apple': r'app[l1]e|app1e|appie',
        'netflix': r'netf[l1][i1]x|netfiix|netfl1x',
        'bank': r'banK|8ank|8ANK',
    }

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile brand patterns."""
        self.compiled_brands = {
            brand: re.compile(pattern, re.IGNORECASE)
            for brand, pattern in self.BRAND_PATTERNS.items()
        }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain for suspicious patterns.

        Returns:
            Dictionary with analysis results
        """
        domain_lower = domain.lower()
        results = {
            'domain': domain,
            'is_legitimate': domain_lower in self.LEGITIMATE_DOMAINS,
            'suspicious_tld': False,
            'brand_impersonation': None,
            'homograph_detected': False,
            'risk_score': 0,
            'indicators': []
        }

        # Check TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                results['suspicious_tld'] = True
                results['risk_score'] += 20
                results['indicators'].append(f'Suspicious TLD: {tld}')
                break

        # Check brand impersonation
        for brand, pattern in self.compiled_brands.items():
            if pattern.search(domain_lower) and brand not in domain_lower:
                results['brand_impersonation'] = brand
                results['risk_score'] += 40
                results['indicators'].append(f'Possible {brand} impersonation')
                break

        # Check for homograph attacks (mixed scripts)
        if self._check_homograph(domain):
            results['homograph_detected'] = True
            results['risk_score'] += 50
            results['indicators'].append('Homograph attack detected')

        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            results['risk_score'] += 15
            results['indicators'].append('Excessive subdomains')

        # Check for IP-like patterns
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            results['risk_score'] += 25
            results['indicators'].append('IP address used as domain')

        return results

    def _check_homograph(self, domain: str) -> bool:
        """Check for homograph/IDN attacks using mixed scripts."""
        # Check for Cyrillic characters that look like Latin
        cyrillic_lookalikes = 'асеорхуАВСЕНКМОРТХ'

        for char in domain:
            if char in cyrillic_lookalikes:
                return True

        return False
