"""
Phone Number Parser and Analyzer Module.

Advanced phone number parsing, validation, and analysis
using phonenumbers library and custom logic.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('scamlytic.algorithms.phone')


@dataclass
class PhoneAnalysisResult:
    """Result of phone number analysis."""
    original_input: str
    normalized: str = ''
    e164_format: str = ''
    national_format: str = ''
    international_format: str = ''

    is_valid: bool = False
    is_possible: bool = False

    country_code: str = ''
    national_number: str = ''
    country_name: str = ''
    region: str = ''

    number_type: str = ''  # mobile, landline, voip, toll_free, etc.
    carrier: str = ''

    # Risk indicators
    is_voip: bool = False
    is_toll_free: bool = False
    is_premium_rate: bool = False
    is_short_code: bool = False

    risk_indicators: List[str] = field(default_factory=list)
    risk_score: int = 0


class PhoneParser:
    """
    Advanced phone number parsing and analysis.
    """

    # Common VoIP prefixes by country
    VOIP_INDICATORS = {
        'US': ['800', '888', '877', '866', '855', '844', '833'],
        'UK': ['03', '070', '076'],
        'NG': ['0700', '0800', '0900'],  # Nigeria
    }

    # Premium rate prefixes
    PREMIUM_PREFIXES = {
        'US': ['900'],
        'UK': ['09', '0871', '0872', '0873'],
        'NG': ['0809'],
    }

    # Nigerian mobile prefixes for carrier detection
    NIGERIAN_CARRIERS = {
        'MTN': ['0803', '0806', '0703', '0706', '0813', '0816', '0810', '0814', '0903', '0906'],
        'Glo': ['0805', '0807', '0705', '0815', '0811', '0905'],
        'Airtel': ['0802', '0808', '0708', '0812', '0701', '0902', '0901', '0907'],
        '9mobile': ['0809', '0817', '0818', '0909', '0908'],
    }

    # Country code to name mapping
    COUNTRY_NAMES = {
        '1': 'United States/Canada',
        '44': 'United Kingdom',
        '234': 'Nigeria',
        '233': 'Ghana',
        '254': 'Kenya',
        '27': 'South Africa',
        '91': 'India',
        '86': 'China',
        '49': 'Germany',
        '33': 'France',
        '39': 'Italy',
        '34': 'Spain',
        '81': 'Japan',
        '82': 'South Korea',
        '55': 'Brazil',
        '52': 'Mexico',
        '7': 'Russia',
        '61': 'Australia',
        '971': 'UAE',
        '966': 'Saudi Arabia',
        '20': 'Egypt',
        '212': 'Morocco',
    }

    def __init__(self):
        self._init_phonenumbers()

    def _init_phonenumbers(self):
        """Initialize phonenumbers library if available."""
        try:
            import phonenumbers
            self.phonenumbers = phonenumbers
            self._has_phonenumbers = True
        except ImportError:
            logger.warning("phonenumbers library not available, using fallback parsing")
            self._has_phonenumbers = False

    def parse(self, phone_input: str, default_region: str = 'US') -> PhoneAnalysisResult:
        """
        Parse and analyze a phone number.

        Args:
            phone_input: The phone number to analyze
            default_region: Default region for parsing (ISO 3166-1 alpha-2)

        Returns:
            PhoneAnalysisResult with complete analysis
        """
        result = PhoneAnalysisResult(original_input=phone_input)

        # Clean input
        cleaned = self._clean_phone_input(phone_input)
        result.normalized = cleaned

        if self._has_phonenumbers:
            return self._parse_with_phonenumbers(result, cleaned, default_region)
        else:
            return self._parse_fallback(result, cleaned)

    def _clean_phone_input(self, phone: str) -> str:
        """Clean phone number input."""
        # Remove common non-numeric characters except +
        cleaned = re.sub(r'[^\d+]', '', phone)

        # Handle various formats
        if cleaned.startswith('00'):
            cleaned = '+' + cleaned[2:]
        elif cleaned.startswith('0') and len(cleaned) > 10:
            # Might be missing country code
            pass

        return cleaned

    def _parse_with_phonenumbers(
        self,
        result: PhoneAnalysisResult,
        phone: str,
        default_region: str
    ) -> PhoneAnalysisResult:
        """Parse using phonenumbers library."""
        try:
            from phonenumbers import (
                parse, is_valid_number, is_possible_number,
                format_number, PhoneNumberFormat, number_type,
                carrier as phone_carrier, geocoder
            )
            from phonenumbers.phonenumberutil import NumberParseException

            # Parse the number
            try:
                parsed = parse(phone, default_region)
            except NumberParseException as e:
                result.is_valid = False
                result.risk_indicators.append('invalid_format')
                return result

            # Basic validation
            result.is_valid = is_valid_number(parsed)
            result.is_possible = is_possible_number(parsed)

            # Format the number
            result.e164_format = format_number(parsed, PhoneNumberFormat.E164)
            result.national_format = format_number(parsed, PhoneNumberFormat.NATIONAL)
            result.international_format = format_number(parsed, PhoneNumberFormat.INTERNATIONAL)

            # Extract components
            result.country_code = str(parsed.country_code)
            result.national_number = str(parsed.national_number)

            # Get country name
            result.country_name = self.COUNTRY_NAMES.get(
                result.country_code,
                geocoder.description_for_number(parsed, 'en')
            )

            # Get region
            try:
                result.region = geocoder.description_for_number(parsed, 'en')
            except Exception:
                pass

            # Get number type
            num_type = number_type(parsed)
            type_names = {
                0: 'landline',
                1: 'mobile',
                2: 'landline_or_mobile',
                3: 'toll_free',
                4: 'premium_rate',
                5: 'shared_cost',
                6: 'voip',
                7: 'personal_number',
                8: 'pager',
                9: 'uan',
                10: 'voicemail',
                -1: 'unknown'
            }
            result.number_type = type_names.get(num_type, 'unknown')

            # Check for VoIP
            result.is_voip = num_type == 6
            result.is_toll_free = num_type == 3
            result.is_premium_rate = num_type == 4

            # Get carrier
            try:
                result.carrier = phone_carrier.name_for_number(parsed, 'en')
            except Exception:
                pass

            # Nigerian specific carrier detection
            if result.country_code == '234':
                result.carrier = self._detect_nigerian_carrier(result.national_format)

        except Exception as e:
            logger.error(f"Phone parsing error: {e}")
            result.is_valid = False
            result.risk_indicators.append('parsing_error')

        # Calculate risk
        self._calculate_risk(result)

        return result

    def _parse_fallback(self, result: PhoneAnalysisResult, phone: str) -> PhoneAnalysisResult:
        """Fallback parsing without phonenumbers library."""
        # Basic validation
        digits_only = re.sub(r'\D', '', phone)

        if len(digits_only) < 7 or len(digits_only) > 15:
            result.is_valid = False
            result.risk_indicators.append('invalid_length')
            return result

        result.is_possible = True

        # Try to detect country code
        if phone.startswith('+'):
            # Extract country code
            for length in [3, 2, 1]:
                potential_cc = digits_only[:length]
                if potential_cc in self.COUNTRY_NAMES:
                    result.country_code = potential_cc
                    result.national_number = digits_only[length:]
                    result.country_name = self.COUNTRY_NAMES[potential_cc]
                    break

        result.e164_format = '+' + digits_only if not phone.startswith('+') else phone

        # Nigerian specific
        if result.country_code == '234' or phone.startswith('0') and len(digits_only) == 11:
            result.carrier = self._detect_nigerian_carrier(phone)
            result.country_code = '234'
            result.country_name = 'Nigeria'
            result.is_valid = True

        # Calculate risk
        self._calculate_risk(result)

        return result

    def _detect_nigerian_carrier(self, phone: str) -> str:
        """Detect Nigerian mobile carrier from phone number."""
        # Normalize to start with 0
        phone = phone.replace(' ', '').replace('-', '')
        if phone.startswith('+234'):
            phone = '0' + phone[4:]
        elif phone.startswith('234'):
            phone = '0' + phone[3:]

        for carrier, prefixes in self.NIGERIAN_CARRIERS.items():
            for prefix in prefixes:
                if phone.startswith(prefix):
                    return carrier

        return 'Unknown'

    def _calculate_risk(self, result: PhoneAnalysisResult):
        """Calculate risk score for phone number."""
        score = 0

        if not result.is_valid:
            score += 30
            result.risk_indicators.append('invalid_number')

        if result.is_voip:
            score += 25
            result.risk_indicators.append('voip_number')

        if result.is_toll_free:
            score += 10
            result.risk_indicators.append('toll_free')

        if result.is_premium_rate:
            score += 20
            result.risk_indicators.append('premium_rate')

        # Unknown carrier for mobile number
        if result.number_type == 'mobile' and not result.carrier:
            score += 10
            result.risk_indicators.append('unknown_carrier')

        # Short codes
        if len(result.national_number) < 7:
            result.is_short_code = True
            score += 15
            result.risk_indicators.append('short_code')

        result.risk_score = min(100, score)

    def extract_phone_numbers(self, text: str) -> List[str]:
        """
        Extract phone numbers from text.

        Returns:
            List of extracted phone numbers
        """
        patterns = [
            # International format
            r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
            # Nigerian format
            r'0[789][01]\d[-.\s]?\d{3}[-.\s]?\d{4}',
            # US format
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            # Generic
            r'\b\d{10,15}\b',
        ]

        found = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            found.extend(matches)

        # Clean and deduplicate
        cleaned = []
        seen = set()
        for phone in found:
            normalized = re.sub(r'[^\d+]', '', phone)
            if len(normalized) >= 7 and normalized not in seen:
                seen.add(normalized)
                cleaned.append(phone)

        return cleaned

    def validate_nigerian_phone(self, phone: str) -> Dict[str, Any]:
        """
        Validate and analyze a Nigerian phone number.

        Returns:
            Dictionary with validation results
        """
        result = {
            'is_valid': False,
            'carrier': None,
            'type': None,
            'formatted': None,
            'errors': []
        }

        # Clean input
        phone = re.sub(r'[^\d+]', '', phone)

        # Handle various formats
        if phone.startswith('+234'):
            phone = '0' + phone[4:]
        elif phone.startswith('234'):
            phone = '0' + phone[3:]

        # Validate length
        if len(phone) != 11:
            result['errors'].append('Nigerian phone numbers must be 11 digits')
            return result

        # Validate prefix
        if not phone.startswith('0'):
            result['errors'].append('Nigerian phone numbers must start with 0')
            return result

        # Validate network prefix
        valid_prefixes = []
        for prefixes in self.NIGERIAN_CARRIERS.values():
            valid_prefixes.extend(prefixes)

        prefix_valid = any(phone.startswith(p) for p in valid_prefixes)
        if not prefix_valid:
            result['errors'].append('Invalid network prefix')
            return result

        result['is_valid'] = True
        result['carrier'] = self._detect_nigerian_carrier(phone)
        result['type'] = 'mobile'
        result['formatted'] = f"+234 {phone[1:4]} {phone[4:7]} {phone[7:]}"

        return result
