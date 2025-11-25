"""
Global ID Detection Module.

Comprehensive detection of identity document phishing attempts
across all regions with primary focus on African nations.

Detects attempts to steal:
- National IDs
- Tax IDs
- Social Security equivalents
- Banking verification numbers
- Passport numbers
- Driver's licenses
- Voter registration
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger('scamlytic.algorithms.id_detector')


class IDRegion(Enum):
    """Geographic regions for ID classification."""
    WEST_AFRICA = 'west_africa'
    EAST_AFRICA = 'east_africa'
    SOUTHERN_AFRICA = 'southern_africa'
    NORTH_AFRICA = 'north_africa'
    NORTH_AMERICA = 'north_america'
    EUROPE = 'europe'
    ASIA = 'asia'
    OCEANIA = 'oceania'
    SOUTH_AMERICA = 'south_america'
    MIDDLE_EAST = 'middle_east'


class IDSeverity(Enum):
    """Severity level of ID theft attempt."""
    CRITICAL = 'critical'  # Direct financial access (BVN, SSN, Aadhaar)
    HIGH = 'high'          # Government ID with verification potential
    MODERATE = 'moderate'  # Secondary identification
    LOW = 'low'            # Supplementary ID info


@dataclass
class IDType:
    """Definition of an ID type."""
    code: str
    name: str
    country: str
    country_code: str
    region: IDRegion
    severity: IDSeverity
    description: str
    format_hint: str
    validation_pattern: Optional[str] = None  # Regex for actual ID validation
    phishing_patterns: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    related_scam_types: List[str] = field(default_factory=list)


@dataclass
class IDDetectionResult:
    """Result of ID phishing detection."""
    detected: bool
    id_types: List[str]
    severity: IDSeverity
    confidence: float
    matched_patterns: List[Dict[str, Any]]
    region: Optional[IDRegion]
    countries: List[str]
    risk_score: int
    recommendations: List[str]


class GlobalIDDetector:
    """
    Comprehensive global ID phishing detector.

    Priority: African IDs first, then global coverage.
    """

    def __init__(self):
        self.id_types = self._initialize_id_types()
        self.compiled_patterns = self._compile_patterns()

    def _initialize_id_types(self) -> Dict[str, IDType]:
        """Initialize all supported ID types."""
        id_types = {}

        # =================================================================
        # WEST AFRICA (Priority Region)
        # =================================================================

        # Nigeria
        id_types['ng_bvn'] = IDType(
            code='ng_bvn',
            name='Bank Verification Number',
            country='Nigeria',
            country_code='NG',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='11-digit number linking all bank accounts in Nigeria',
            format_hint='11 digits',
            validation_pattern=r'\b[0-9]{11}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|enter|submit|send)\s+(?:your\s+)?bvn',
                r'bvn\s+(?:number|details|information|verification|update|required)',
                r'bank\s+verification\s+number',
                r'bvn\s+(?:is\s+)?(?:expir|block|suspend|deactivat)',
                r'link\s+(?:your\s+)?bvn',
                r'bvn\s+enrol(?:l)?ment',
                r'(?:cbn|central\s+bank).*bvn',
                r'bvn:\s*[0-9]{11}',
            ],
            keywords=['bvn', 'bank verification number', 'cbn', 'nibss'],
            related_scam_types=['BVN_PHISHING', 'BANK_IMPERSONATION']
        )

        id_types['ng_nin'] = IDType(
            code='ng_nin',
            name='National Identification Number',
            country='Nigeria',
            country_code='NG',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='11-digit unique identifier issued by NIMC',
            format_hint='11 digits',
            validation_pattern=r'\b[0-9]{11}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|enter|submit|send)\s+(?:your\s+)?nin',
                r'nin\s+(?:number|details|information|verification|slip|required)',
                r'national\s+(?:identification|identity)\s+number',
                r'nin\s+(?:is\s+)?(?:expir|block|suspend|deactivat|mandatory)',
                r'link\s+(?:your\s+)?nin',
                r'nimc.*nin',
                r'nin\s+(?:enrol(?:l)?ment|registration)',
                r'nin:\s*[0-9]{11}',
            ],
            keywords=['nin', 'nimc', 'national identification number', 'national identity'],
            related_scam_types=['NIN_PHISHING', 'GOVERNMENT_SCAM']
        )

        id_types['ng_voters_card'] = IDType(
            code='ng_voters_card',
            name='Permanent Voter\'s Card',
            country='Nigeria',
            country_code='NG',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.HIGH,
            description='Voter identification card issued by INEC',
            format_hint='19 alphanumeric characters',
            validation_pattern=r'\b[A-Z0-9]{19}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:pvc|voter)',
                r'(?:pvc|voter.?s?\s+card)\s+(?:number|details|collection|verification)',
                r'inec.*(?:pvc|voter)',
                r'permanent\s+voter',
            ],
            keywords=['pvc', 'voters card', 'inec', 'permanent voter'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        id_types['ng_drivers_license'] = IDType(
            code='ng_drivers_license',
            name='Driver\'s License',
            country='Nigeria',
            country_code='NG',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.MODERATE,
            description='Nigerian driver\'s license issued by FRSC',
            format_hint='12 alphanumeric characters',
            phishing_patterns=[
                r'(?:update|verify|renew)\s+(?:your\s+)?(?:driver|driving)\s*(?:\'s)?\s*licen[cs]e',
                r'frsc.*(?:driver|licen[cs]e)',
                r'(?:driver|driving)\s*(?:\'s)?\s*licen[cs]e\s+(?:expir|renew|verif)',
            ],
            keywords=['drivers license', 'frsc', 'driving licence'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Ghana
        id_types['gh_ghana_card'] = IDType(
            code='gh_ghana_card',
            name='Ghana Card',
            country='Ghana',
            country_code='GH',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='National identification card with unique PIN',
            format_hint='GHA-XXXXXXXXX-X format',
            validation_pattern=r'\bGHA-[0-9]{9}-[0-9]\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?ghana\s+card',
                r'ghana\s+card\s+(?:number|pin|details|verification)',
                r'nia.*ghana\s+card',
                r'national\s+identification\s+authority.*ghana',
                r'ghana\s+card\s+(?:expir|block|suspend)',
            ],
            keywords=['ghana card', 'nia', 'national identification authority'],
            related_scam_types=['GOVERNMENT_SCAM', 'BANK_IMPERSONATION']
        )

        id_types['gh_tin'] = IDType(
            code='gh_tin',
            name='Tax Identification Number',
            country='Ghana',
            country_code='GH',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.HIGH,
            description='Ghana Revenue Authority tax ID',
            format_hint='Alphanumeric',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:ghana\s+)?tin',
                r'tax\s+identification\s+number.*ghana',
                r'gra.*tin',
            ],
            keywords=['tin', 'gra', 'ghana revenue'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # Senegal
        id_types['sn_cni'] = IDType(
            code='sn_cni',
            name='Carte Nationale d\'Identité',
            country='Senegal',
            country_code='SN',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.HIGH,
            description='Senegalese national ID card',
            format_hint='13 digits',
            validation_pattern=r'\b[0-9]{13}\b',
            phishing_patterns=[
                r'(?:mettre à jour|vérifier|confirmer)\s+(?:votre\s+)?cni',
                r'carte\s+nationale\s+d\'identité',
                r'numéro\s+cni',
            ],
            keywords=['cni', 'carte nationale', 'identité'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Côte d'Ivoire
        id_types['ci_cni'] = IDType(
            code='ci_cni',
            name='Carte Nationale d\'Identité',
            country='Côte d\'Ivoire',
            country_code='CI',
            region=IDRegion.WEST_AFRICA,
            severity=IDSeverity.HIGH,
            description='Ivorian national ID card',
            format_hint='Alphanumeric',
            phishing_patterns=[
                r'(?:mettre à jour|vérifier)\s+(?:votre\s+)?cni',
                r'carte\s+nationale.*ivoire',
                r'oneci.*identité',
            ],
            keywords=['cni', 'oneci', 'carte identité'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # EAST AFRICA
        # =================================================================

        # Kenya
        id_types['ke_national_id'] = IDType(
            code='ke_national_id',
            name='National ID',
            country='Kenya',
            country_code='KE',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Kenyan national identification card',
            format_hint='8 digits',
            validation_pattern=r'\b[0-9]{8}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:national\s+)?id',
                r'national\s+id\s+(?:number|card|details|verification)',
                r'huduma\s+(?:namba|number)',
                r'kra\s+pin.*id',
                r'id\s+(?:number|card)\s+(?:expir|block|suspend)',
            ],
            keywords=['national id', 'huduma namba', 'kitambulisho'],
            related_scam_types=['GOVERNMENT_SCAM', 'BANK_IMPERSONATION']
        )

        id_types['ke_kra_pin'] = IDType(
            code='ke_kra_pin',
            name='KRA PIN',
            country='Kenya',
            country_code='KE',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Kenya Revenue Authority Personal Identification Number',
            format_hint='A + 9 digits + letter (e.g., A123456789B)',
            validation_pattern=r'\b[A-Z][0-9]{9}[A-Z]\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?kra\s+pin',
                r'kra\s+pin\s+(?:number|certificate|details|verification)',
                r'kenya\s+revenue.*pin',
                r'itax.*pin',
                r'kra\s+pin\s+(?:expir|block|suspend)',
            ],
            keywords=['kra pin', 'kenya revenue', 'itax'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['ke_mpesa'] = IDType(
            code='ke_mpesa',
            name='M-Pesa PIN',
            country='Kenya',
            country_code='KE',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='M-Pesa mobile money PIN',
            format_hint='4 digit PIN',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|enter)\s+(?:your\s+)?m[\-\s]?pesa\s+pin',
                r'm[\-\s]?pesa\s+(?:pin|password|code|details)',
                r'safaricom.*m[\-\s]?pesa.*pin',
                r'm[\-\s]?pesa\s+(?:suspend|block|limit)',
                r'(?:till|paybill).*m[\-\s]?pesa.*pin',
            ],
            keywords=['mpesa', 'm-pesa', 'safaricom', 'paybill'],
            related_scam_types=['MOBILE_MONEY_SCAM', 'BANK_IMPERSONATION']
        )

        # Tanzania
        id_types['tz_nida'] = IDType(
            code='tz_nida',
            name='NIDA ID',
            country='Tanzania',
            country_code='TZ',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='National Identification Authority ID',
            format_hint='20 digits',
            validation_pattern=r'\b[0-9]{20}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?nida',
                r'nida\s+(?:number|id|card|details)',
                r'national\s+identification.*tanzania',
            ],
            keywords=['nida', 'kitambulisho', 'tanzania id'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Uganda
        id_types['ug_national_id'] = IDType(
            code='ug_national_id',
            name='National ID',
            country='Uganda',
            country_code='UG',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Ugandan national identification card',
            format_hint='14 alphanumeric characters',
            validation_pattern=r'\b[A-Z]{2}[0-9]{12}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:national\s+)?id',
                r'nira.*id',
                r'national\s+id.*uganda',
            ],
            keywords=['national id', 'nira', 'ndagamuntu'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Rwanda
        id_types['rw_national_id'] = IDType(
            code='rw_national_id',
            name='National ID',
            country='Rwanda',
            country_code='RW',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Rwandan national identification number',
            format_hint='16 digits',
            validation_pattern=r'\b[0-9]{16}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:national\s+)?id',
                r'nida.*rwanda',
                r'indangamuntu',
            ],
            keywords=['national id', 'nida', 'indangamuntu'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Ethiopia
        id_types['et_fayda_id'] = IDType(
            code='et_fayda_id',
            name='Fayda Digital ID',
            country='Ethiopia',
            country_code='ET',
            region=IDRegion.EAST_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Ethiopian digital ID system',
            format_hint='12 digits',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?fayda',
                r'fayda\s+(?:id|number|digital)',
                r'ethiopian\s+digital\s+id',
            ],
            keywords=['fayda', 'digital id', 'ethiopia id'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # SOUTHERN AFRICA
        # =================================================================

        # South Africa
        id_types['za_id_number'] = IDType(
            code='za_id_number',
            name='ID Number',
            country='South Africa',
            country_code='ZA',
            region=IDRegion.SOUTHERN_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='13-digit South African ID number',
            format_hint='13 digits (YYMMDD + gender + citizenship + checksum)',
            validation_pattern=r'\b[0-9]{13}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:sa\s+)?id\s+number',
                r'id\s+number\s+(?:verification|details|required)',
                r'home\s+affairs.*id',
                r'smart\s+id\s+card',
                r'id\s+(?:number|card)\s+(?:expir|block|suspend)',
            ],
            keywords=['id number', 'home affairs', 'smart id'],
            related_scam_types=['GOVERNMENT_SCAM', 'BANK_IMPERSONATION']
        )

        id_types['za_tax_number'] = IDType(
            code='za_tax_number',
            name='Tax Reference Number',
            country='South Africa',
            country_code='ZA',
            region=IDRegion.SOUTHERN_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='SARS tax reference number',
            format_hint='10 digits',
            validation_pattern=r'\b[0-9]{10}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:sars\s+)?tax\s+(?:number|reference)',
                r'sars.*tax.*(?:number|refund|return)',
                r'tax\s+(?:reference|number)\s+(?:verification|required)',
                r'efiling.*tax',
            ],
            keywords=['sars', 'tax number', 'efiling', 'tax reference'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # Zimbabwe
        id_types['zw_national_id'] = IDType(
            code='zw_national_id',
            name='National ID',
            country='Zimbabwe',
            country_code='ZW',
            region=IDRegion.SOUTHERN_AFRICA,
            severity=IDSeverity.HIGH,
            description='Zimbabwean national ID',
            format_hint='XX-XXXXXX-X-XX format',
            validation_pattern=r'\b[0-9]{2}-[0-9]{6,7}-[A-Z]-[0-9]{2}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:national\s+)?id',
                r'national\s+registration.*zimbabwe',
            ],
            keywords=['national id', 'registrar general'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Botswana
        id_types['bw_omang'] = IDType(
            code='bw_omang',
            name='Omang',
            country='Botswana',
            country_code='BW',
            region=IDRegion.SOUTHERN_AFRICA,
            severity=IDSeverity.HIGH,
            description='Botswana national identity card',
            format_hint='9 digits',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?omang',
                r'omang\s+(?:number|card|details)',
            ],
            keywords=['omang', 'botswana id'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # NORTH AFRICA
        # =================================================================

        # Egypt
        id_types['eg_national_id'] = IDType(
            code='eg_national_id',
            name='National ID',
            country='Egypt',
            country_code='EG',
            region=IDRegion.NORTH_AFRICA,
            severity=IDSeverity.CRITICAL,
            description='Egyptian national identification number',
            format_hint='14 digits',
            validation_pattern=r'\b[0-9]{14}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:national\s+)?id',
                r'رقم\s+(?:البطاقة|القومي)',
                r'national\s+id.*egypt',
            ],
            keywords=['national id', 'رقم القومي', 'بطاقة'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Morocco
        id_types['ma_cin'] = IDType(
            code='ma_cin',
            name='Carte d\'Identité Nationale (CIN)',
            country='Morocco',
            country_code='MA',
            region=IDRegion.NORTH_AFRICA,
            severity=IDSeverity.HIGH,
            description='Moroccan national identity card',
            format_hint='Alphanumeric',
            phishing_patterns=[
                r'(?:mettre à jour|vérifier)\s+(?:votre\s+)?cin',
                r'carte\s+d\'identité\s+nationale',
                r'cin\s+(?:numéro|carte)',
            ],
            keywords=['cin', 'carte identité', 'بطاقة التعريف'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Algeria
        id_types['dz_national_id'] = IDType(
            code='dz_national_id',
            name='Carte Nationale d\'Identité',
            country='Algeria',
            country_code='DZ',
            region=IDRegion.NORTH_AFRICA,
            severity=IDSeverity.HIGH,
            description='Algerian national ID card',
            format_hint='18 digits',
            validation_pattern=r'\b[0-9]{18}\b',
            phishing_patterns=[
                r'(?:mettre à jour|vérifier)\s+(?:votre\s+)?(?:cni|carte)',
                r'carte\s+nationale.*algérie',
                r'رقم\s+التعريف',
            ],
            keywords=['carte nationale', 'بطاقة التعريف'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # NORTH AMERICA
        # =================================================================

        # United States
        id_types['us_ssn'] = IDType(
            code='us_ssn',
            name='Social Security Number',
            country='United States',
            country_code='US',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.CRITICAL,
            description='9-digit US Social Security Number',
            format_hint='XXX-XX-XXXX or 9 digits',
            validation_pattern=r'\b[0-9]{3}-?[0-9]{2}-?[0-9]{4}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|enter)\s+(?:your\s+)?(?:social\s+security|ssn)',
                r'social\s+security\s+(?:number|card|benefits)',
                r'ssn\s+(?:verification|required|suspended|compromised)',
                r'(?:irs|ssa).*(?:ssn|social\s+security)',
                r'(?:ssn|social\s+security)\s+(?:has\s+been\s+)?(?:suspend|compromis|block)',
            ],
            keywords=['ssn', 'social security', 'ssa', 'irs'],
            related_scam_types=['SSN_PHISHING', 'TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['us_itin'] = IDType(
            code='us_itin',
            name='Individual Taxpayer Identification Number',
            country='United States',
            country_code='US',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.CRITICAL,
            description='IRS ITIN for tax purposes',
            format_hint='9XX-XX-XXXX',
            validation_pattern=r'\b9[0-9]{2}-?[0-9]{2}-?[0-9]{4}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?itin',
                r'itin\s+(?:number|verification|renewal)',
                r'(?:irs).*itin',
            ],
            keywords=['itin', 'irs', 'taxpayer identification'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['us_ein'] = IDType(
            code='us_ein',
            name='Employer Identification Number',
            country='United States',
            country_code='US',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.HIGH,
            description='IRS EIN for businesses',
            format_hint='XX-XXXXXXX',
            validation_pattern=r'\b[0-9]{2}-?[0-9]{7}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?ein',
                r'ein\s+(?:number|verification)',
                r'employer\s+identification',
            ],
            keywords=['ein', 'employer identification'],
            related_scam_types=['BUSINESS_SCAM', 'TAX_SCAM']
        )

        # Canada
        id_types['ca_sin'] = IDType(
            code='ca_sin',
            name='Social Insurance Number',
            country='Canada',
            country_code='CA',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.CRITICAL,
            description='9-digit Canadian SIN',
            format_hint='XXX-XXX-XXX or 9 digits',
            validation_pattern=r'\b[0-9]{3}-?[0-9]{3}-?[0-9]{3}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:social\s+insurance|sin)',
                r'sin\s+(?:number|card|verification)',
                r'(?:cra|service\s+canada).*sin',
                r'sin\s+(?:suspend|compromis|block)',
            ],
            keywords=['sin', 'social insurance', 'cra', 'service canada'],
            related_scam_types=['SIN_PHISHING', 'TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # Mexico
        id_types['mx_curp'] = IDType(
            code='mx_curp',
            name='CURP',
            country='Mexico',
            country_code='MX',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.CRITICAL,
            description='Clave Única de Registro de Población',
            format_hint='18 alphanumeric characters',
            validation_pattern=r'\b[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[0-9A-Z][0-9]\b',
            phishing_patterns=[
                r'(?:actualizar|verificar|proporcionar)\s+(?:tu\s+)?curp',
                r'curp\s+(?:número|verificación)',
                r'clave\s+única',
            ],
            keywords=['curp', 'clave única', 'registro población'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        id_types['mx_rfc'] = IDType(
            code='mx_rfc',
            name='RFC',
            country='Mexico',
            country_code='MX',
            region=IDRegion.NORTH_AMERICA,
            severity=IDSeverity.HIGH,
            description='Registro Federal de Contribuyentes (Tax ID)',
            format_hint='13 characters for individuals',
            validation_pattern=r'\b[A-Z]{4}[0-9]{6}[A-Z0-9]{3}\b',
            phishing_patterns=[
                r'(?:actualizar|verificar|proporcionar)\s+(?:tu\s+)?rfc',
                r'rfc\s+(?:número|verificación)',
                r'sat.*rfc',
            ],
            keywords=['rfc', 'sat', 'contribuyentes'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # =================================================================
        # EUROPE
        # =================================================================

        # United Kingdom
        id_types['gb_nino'] = IDType(
            code='gb_nino',
            name='National Insurance Number',
            country='United Kingdom',
            country_code='GB',
            region=IDRegion.EUROPE,
            severity=IDSeverity.CRITICAL,
            description='UK National Insurance number',
            format_hint='2 letters + 6 digits + 1 letter',
            validation_pattern=r'\b[A-Z]{2}[0-9]{6}[A-Z]\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:national\s+insurance|ni|nino)',
                r'national\s+insurance\s+(?:number|ni)\s+(?:verification|required)',
                r'(?:hmrc|dwp).*(?:ni|national\s+insurance)',
                r'ni\s+number\s+(?:suspend|compromis|block)',
            ],
            keywords=['national insurance', 'ni number', 'nino', 'hmrc'],
            related_scam_types=['NI_PHISHING', 'TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['gb_utr'] = IDType(
            code='gb_utr',
            name='Unique Taxpayer Reference',
            country='United Kingdom',
            country_code='GB',
            region=IDRegion.EUROPE,
            severity=IDSeverity.HIGH,
            description='10-digit HMRC tax reference',
            format_hint='10 digits',
            validation_pattern=r'\b[0-9]{10}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?utr',
                r'utr\s+(?:number|reference)',
                r'unique\s+taxpayer\s+reference',
                r'hmrc.*utr',
            ],
            keywords=['utr', 'hmrc', 'taxpayer reference'],
            related_scam_types=['TAX_SCAM']
        )

        # Germany
        id_types['de_steuer_id'] = IDType(
            code='de_steuer_id',
            name='Steueridentifikationsnummer',
            country='Germany',
            country_code='DE',
            region=IDRegion.EUROPE,
            severity=IDSeverity.CRITICAL,
            description='11-digit German tax ID',
            format_hint='11 digits',
            validation_pattern=r'\b[0-9]{11}\b',
            phishing_patterns=[
                r'(?:aktualisieren|bestätigen|angeben)\s+(?:ihre\s+)?(?:steuer-?id|steuernummer)',
                r'steuer(?:identifikations)?nummer',
                r'finanzamt.*steuer',
            ],
            keywords=['steuer-id', 'steuernummer', 'finanzamt'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['de_personalausweis'] = IDType(
            code='de_personalausweis',
            name='Personalausweis',
            country='Germany',
            country_code='DE',
            region=IDRegion.EUROPE,
            severity=IDSeverity.HIGH,
            description='German ID card number',
            format_hint='10 alphanumeric',
            phishing_patterns=[
                r'(?:aktualisieren|bestätigen)\s+(?:ihren?\s+)?personalausweis',
                r'personalausweis(?:nummer)?',
                r'ausweisnummer',
            ],
            keywords=['personalausweis', 'ausweis'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # France
        id_types['fr_numero_secu'] = IDType(
            code='fr_numero_secu',
            name='Numéro de Sécurité Sociale',
            country='France',
            country_code='FR',
            region=IDRegion.EUROPE,
            severity=IDSeverity.CRITICAL,
            description='15-digit French social security number',
            format_hint='15 digits',
            validation_pattern=r'\b[12][0-9]{14}\b',
            phishing_patterns=[
                r'(?:mettre à jour|vérifier|fournir)\s+(?:votre\s+)?(?:numéro\s+)?(?:sécu|sécurité\s+sociale)',
                r'numéro\s+de\s+sécurité\s+sociale',
                r'carte\s+vitale',
                r'ameli.*numéro',
            ],
            keywords=['sécu', 'sécurité sociale', 'carte vitale', 'ameli'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Italy
        id_types['it_codice_fiscale'] = IDType(
            code='it_codice_fiscale',
            name='Codice Fiscale',
            country='Italy',
            country_code='IT',
            region=IDRegion.EUROPE,
            severity=IDSeverity.CRITICAL,
            description='Italian tax code',
            format_hint='16 alphanumeric characters',
            validation_pattern=r'\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b',
            phishing_patterns=[
                r'(?:aggiornare|verificare|fornire)\s+(?:il\s+)?codice\s+fiscale',
                r'codice\s+fiscale',
                r'agenzia.*entrate.*codice',
            ],
            keywords=['codice fiscale', 'agenzia entrate'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # Spain
        id_types['es_dni'] = IDType(
            code='es_dni',
            name='DNI/NIE',
            country='Spain',
            country_code='ES',
            region=IDRegion.EUROPE,
            severity=IDSeverity.HIGH,
            description='Spanish national ID',
            format_hint='8 digits + letter or X/Y/Z + 7 digits + letter',
            validation_pattern=r'\b[0-9]{8}[A-Z]\b|\b[XYZ][0-9]{7}[A-Z]\b',
            phishing_patterns=[
                r'(?:actualizar|verificar|proporcionar)\s+(?:tu\s+)?(?:dni|nie)',
                r'(?:dni|nie)\s+(?:número|verificación)',
                r'documento\s+nacional\s+de\s+identidad',
            ],
            keywords=['dni', 'nie', 'documento identidad'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Netherlands
        id_types['nl_bsn'] = IDType(
            code='nl_bsn',
            name='Burgerservicenummer (BSN)',
            country='Netherlands',
            country_code='NL',
            region=IDRegion.EUROPE,
            severity=IDSeverity.CRITICAL,
            description='9-digit Dutch citizen service number',
            format_hint='9 digits',
            validation_pattern=r'\b[0-9]{9}\b',
            phishing_patterns=[
                r'(?:bijwerken|verifiëren|verstrekken)\s+(?:uw\s+)?bsn',
                r'bsn\s+(?:nummer|verificatie)',
                r'burgerservicenummer',
                r'digid.*bsn',
            ],
            keywords=['bsn', 'burgerservicenummer', 'digid'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # ASIA
        # =================================================================

        # India
        id_types['in_aadhaar'] = IDType(
            code='in_aadhaar',
            name='Aadhaar',
            country='India',
            country_code='IN',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='12-digit unique identification number',
            format_hint='12 digits',
            validation_pattern=r'\b[0-9]{12}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|link)\s+(?:your\s+)?(?:aadhaar|aadhar)',
                r'(?:aadhaar|aadhar)\s+(?:number|card|verification|otp|linking)',
                r'uidai.*(?:aadhaar|aadhar)',
                r'(?:aadhaar|aadhar)\s+(?:suspend|deactivat|block)',
                r'link\s+(?:aadhaar|aadhar)\s+(?:with|to)',
            ],
            keywords=['aadhaar', 'aadhar', 'uidai', 'unique identification'],
            related_scam_types=['AADHAAR_PHISHING', 'BANK_IMPERSONATION', 'GOVERNMENT_SCAM']
        )

        id_types['in_pan'] = IDType(
            code='in_pan',
            name='PAN',
            country='India',
            country_code='IN',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='Permanent Account Number (10 characters)',
            format_hint='5 letters + 4 digits + 1 letter',
            validation_pattern=r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide|link)\s+(?:your\s+)?pan',
                r'pan\s+(?:card|number|verification|linking)',
                r'(?:income\s+tax|it\s+department).*pan',
                r'pan\s+(?:suspend|deactivat|block)',
                r'link\s+pan\s+(?:with|to)\s+(?:aadhaar|aadhar)',
            ],
            keywords=['pan', 'pan card', 'income tax', 'permanent account'],
            related_scam_types=['PAN_PHISHING', 'TAX_SCAM']
        )

        id_types['in_upi'] = IDType(
            code='in_upi',
            name='UPI PIN',
            country='India',
            country_code='IN',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='UPI transaction PIN',
            format_hint='4-6 digit PIN',
            phishing_patterns=[
                r'(?:update|verify|provide|enter)\s+(?:your\s+)?upi\s+pin',
                r'upi\s+(?:pin|id|password)',
                r'(?:gpay|phonepe|paytm).*(?:pin|otp)',
                r'upi\s+(?:suspend|block|limit)',
            ],
            keywords=['upi', 'upi pin', 'gpay', 'phonepe', 'paytm'],
            related_scam_types=['UPI_SCAM', 'MOBILE_MONEY_SCAM']
        )

        # China
        id_types['cn_shenfenzheng'] = IDType(
            code='cn_shenfenzheng',
            name='Resident Identity Card',
            country='China',
            country_code='CN',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='18-digit Chinese ID number',
            format_hint='18 digits',
            validation_pattern=r'\b[0-9]{17}[0-9X]\b',
            phishing_patterns=[
                r'(?:更新|验证|提供)\s*(?:您的\s*)?身份证',
                r'身份证\s*(?:号码|验证)',
                r'(?:update|verify)\s+(?:your\s+)?(?:id|identity)\s+(?:card|number)',
            ],
            keywords=['身份证', 'shenfenzheng', 'resident id'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Japan
        id_types['jp_my_number'] = IDType(
            code='jp_my_number',
            name='My Number',
            country='Japan',
            country_code='JP',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='12-digit Japanese social security and tax number',
            format_hint='12 digits',
            validation_pattern=r'\b[0-9]{12}\b',
            phishing_patterns=[
                r'(?:更新|確認|提供)\s*(?:あなたの\s*)?マイナンバー',
                r'マイナンバー\s*(?:番号|カード|確認)',
                r'my\s+number\s+(?:card|verification)',
            ],
            keywords=['マイナンバー', 'my number', 'mynumber'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # South Korea
        id_types['kr_rrn'] = IDType(
            code='kr_rrn',
            name='Resident Registration Number',
            country='South Korea',
            country_code='KR',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='13-digit Korean RRN',
            format_hint='6 digits + 7 digits',
            validation_pattern=r'\b[0-9]{6}-?[1-4][0-9]{6}\b',
            phishing_patterns=[
                r'(?:업데이트|확인|제공)\s*(?:귀하의\s*)?주민등록번호',
                r'주민등록번호\s*(?:확인|필요)',
                r'resident\s+registration\s+number',
            ],
            keywords=['주민등록번호', 'rrn', 'resident registration'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Singapore
        id_types['sg_nric'] = IDType(
            code='sg_nric',
            name='NRIC/FIN',
            country='Singapore',
            country_code='SG',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='Singapore National Registration Identity Card',
            format_hint='1 letter + 7 digits + 1 letter',
            validation_pattern=r'\b[STFG][0-9]{7}[A-Z]\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:nric|fin)',
                r'(?:nric|fin)\s+(?:number|verification)',
                r'singpass.*(?:nric|fin)',
            ],
            keywords=['nric', 'fin', 'singpass'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Philippines
        id_types['ph_philsys'] = IDType(
            code='ph_philsys',
            name='PhilSys ID (National ID)',
            country='Philippines',
            country_code='PH',
            region=IDRegion.ASIA,
            severity=IDSeverity.CRITICAL,
            description='Philippine Identification System ID',
            format_hint='12 digits',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?(?:philsys|national\s+id|psn)',
                r'(?:philsys|psn)\s+(?:number|id|verification)',
                r'philippine\s+(?:identification|national\s+id)',
            ],
            keywords=['philsys', 'psn', 'national id'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # =================================================================
        # OCEANIA
        # =================================================================

        # Australia
        id_types['au_tfn'] = IDType(
            code='au_tfn',
            name='Tax File Number',
            country='Australia',
            country_code='AU',
            region=IDRegion.OCEANIA,
            severity=IDSeverity.CRITICAL,
            description='9-digit Australian TFN',
            format_hint='9 digits',
            validation_pattern=r'\b[0-9]{9}\b',
            phishing_patterns=[
                r'(?:update|verify|confirm|provide)\s+(?:your\s+)?(?:tfn|tax\s+file)',
                r'(?:tfn|tax\s+file\s+number)\s+(?:verification|required)',
                r'(?:ato|mygov).*(?:tfn|tax\s+file)',
                r'(?:tfn|tax\s+file)\s+(?:suspend|compromis)',
            ],
            keywords=['tfn', 'tax file number', 'ato', 'mygov'],
            related_scam_types=['TFN_PHISHING', 'TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        id_types['au_medicare'] = IDType(
            code='au_medicare',
            name='Medicare Number',
            country='Australia',
            country_code='AU',
            region=IDRegion.OCEANIA,
            severity=IDSeverity.HIGH,
            description='10-digit Medicare card number',
            format_hint='10 digits',
            validation_pattern=r'\b[0-9]{10}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?medicare',
                r'medicare\s+(?:number|card|verification)',
                r'services\s+australia.*medicare',
            ],
            keywords=['medicare', 'services australia'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # New Zealand
        id_types['nz_ird'] = IDType(
            code='nz_ird',
            name='IRD Number',
            country='New Zealand',
            country_code='NZ',
            region=IDRegion.OCEANIA,
            severity=IDSeverity.CRITICAL,
            description='8-9 digit Inland Revenue Department number',
            format_hint='8-9 digits',
            validation_pattern=r'\b[0-9]{8,9}\b',
            phishing_patterns=[
                r'(?:update|verify|provide)\s+(?:your\s+)?ird',
                r'ird\s+(?:number|verification)',
                r'inland\s+revenue.*(?:number|ird)',
            ],
            keywords=['ird', 'inland revenue'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # =================================================================
        # SOUTH AMERICA
        # =================================================================

        # Brazil
        id_types['br_cpf'] = IDType(
            code='br_cpf',
            name='CPF',
            country='Brazil',
            country_code='BR',
            region=IDRegion.SOUTH_AMERICA,
            severity=IDSeverity.CRITICAL,
            description='Cadastro de Pessoas Físicas (11 digits)',
            format_hint='XXX.XXX.XXX-XX',
            validation_pattern=r'\b[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}-?[0-9]{2}\b',
            phishing_patterns=[
                r'(?:atualizar|verificar|fornecer)\s+(?:seu\s+)?cpf',
                r'cpf\s+(?:número|verificação|pendente)',
                r'receita\s+federal.*cpf',
            ],
            keywords=['cpf', 'receita federal', 'cadastro'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # Argentina
        id_types['ar_cuit'] = IDType(
            code='ar_cuit',
            name='CUIT/CUIL',
            country='Argentina',
            country_code='AR',
            region=IDRegion.SOUTH_AMERICA,
            severity=IDSeverity.HIGH,
            description='Argentine tax identification',
            format_hint='XX-XXXXXXXX-X',
            validation_pattern=r'\b[0-9]{2}-?[0-9]{8}-?[0-9]\b',
            phishing_patterns=[
                r'(?:actualizar|verificar|proporcionar)\s+(?:tu\s+)?(?:cuit|cuil)',
                r'(?:cuit|cuil)\s+(?:número|verificación)',
                r'afip.*(?:cuit|cuil)',
            ],
            keywords=['cuit', 'cuil', 'afip'],
            related_scam_types=['TAX_SCAM', 'GOVERNMENT_SCAM']
        )

        # =================================================================
        # MIDDLE EAST
        # =================================================================

        # UAE
        id_types['ae_emirates_id'] = IDType(
            code='ae_emirates_id',
            name='Emirates ID',
            country='United Arab Emirates',
            country_code='AE',
            region=IDRegion.MIDDLE_EAST,
            severity=IDSeverity.CRITICAL,
            description='15-digit UAE identity card number',
            format_hint='784-XXXX-XXXXXXX-X',
            validation_pattern=r'\b784-?[0-9]{4}-?[0-9]{7}-?[0-9]\b',
            phishing_patterns=[
                r'(?:update|verify|renew)\s+(?:your\s+)?emirates\s+id',
                r'emirates\s+id\s+(?:number|renewal|expir)',
                r'ica.*emirates\s+id',
            ],
            keywords=['emirates id', 'ica', 'هوية الإمارات'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        # Saudi Arabia
        id_types['sa_iqama'] = IDType(
            code='sa_iqama',
            name='Iqama',
            country='Saudi Arabia',
            country_code='SA',
            region=IDRegion.MIDDLE_EAST,
            severity=IDSeverity.HIGH,
            description='Saudi resident ID',
            format_hint='10 digits',
            validation_pattern=r'\b[12][0-9]{9}\b',
            phishing_patterns=[
                r'(?:update|verify|renew)\s+(?:your\s+)?iqama',
                r'iqama\s+(?:number|renewal|expir)',
                r'absher.*iqama',
                r'إقامة',
            ],
            keywords=['iqama', 'absher', 'إقامة'],
            related_scam_types=['GOVERNMENT_SCAM']
        )

        return id_types

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile all regex patterns for efficiency."""
        compiled = {}
        for id_code, id_type in self.id_types.items():
            compiled[id_code] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in id_type.phishing_patterns
            ]
        return compiled

    def detect(self, text: str) -> IDDetectionResult:
        """
        Detect ID phishing attempts in text.

        Args:
            text: Text to analyze

        Returns:
            IDDetectionResult with detected IDs and risk assessment
        """
        detected_ids = []
        matched_patterns = []
        countries = set()
        regions = set()
        max_severity = IDSeverity.LOW

        text_lower = text.lower()

        # Check each ID type
        for id_code, patterns in self.compiled_patterns.items():
            id_type = self.id_types[id_code]

            # Quick keyword check first for efficiency
            has_keyword = any(kw in text_lower for kw in id_type.keywords)

            if has_keyword:
                for pattern in patterns:
                    matches = pattern.findall(text)
                    if matches:
                        detected_ids.append(id_code)
                        countries.add(id_type.country)
                        regions.add(id_type.region)

                        matched_patterns.append({
                            'id_type': id_code,
                            'id_name': id_type.name,
                            'country': id_type.country,
                            'region': id_type.region.value,
                            'severity': id_type.severity.value,
                            'pattern_matched': pattern.pattern,
                            'matches': matches[:3],  # Limit stored matches
                        })

                        # Track max severity
                        if self._severity_rank(id_type.severity) > self._severity_rank(max_severity):
                            max_severity = id_type.severity

                        break  # One match per ID type is enough

        # Calculate risk score
        risk_score = self._calculate_risk_score(detected_ids, max_severity, len(matched_patterns))

        # Generate recommendations
        recommendations = self._generate_recommendations(detected_ids, max_severity)

        return IDDetectionResult(
            detected=len(detected_ids) > 0,
            id_types=detected_ids,
            severity=max_severity,
            confidence=min(0.95, 0.5 + len(detected_ids) * 0.15),
            matched_patterns=matched_patterns,
            region=list(regions)[0] if len(regions) == 1 else None,
            countries=list(countries),
            risk_score=risk_score,
            recommendations=recommendations
        )

    def detect_by_region(self, text: str, region: IDRegion) -> IDDetectionResult:
        """Detect ID phishing for a specific region."""
        # Filter to only check IDs from specified region
        regional_ids = {
            code: patterns
            for code, patterns in self.compiled_patterns.items()
            if self.id_types[code].region == region
        }

        # Temporarily swap patterns
        original_patterns = self.compiled_patterns
        self.compiled_patterns = regional_ids

        result = self.detect(text)

        # Restore
        self.compiled_patterns = original_patterns

        return result

    def detect_african_ids(self, text: str) -> IDDetectionResult:
        """Specifically detect African ID phishing attempts."""
        african_regions = [
            IDRegion.WEST_AFRICA,
            IDRegion.EAST_AFRICA,
            IDRegion.SOUTHERN_AFRICA,
            IDRegion.NORTH_AFRICA
        ]

        african_ids = {
            code: patterns
            for code, patterns in self.compiled_patterns.items()
            if self.id_types[code].region in african_regions
        }

        original_patterns = self.compiled_patterns
        self.compiled_patterns = african_ids

        result = self.detect(text)

        self.compiled_patterns = original_patterns

        return result

    def get_id_info(self, id_code: str) -> Optional[IDType]:
        """Get information about a specific ID type."""
        return self.id_types.get(id_code)

    def list_ids_by_country(self, country_code: str) -> List[IDType]:
        """List all ID types for a country."""
        return [
            id_type for id_type in self.id_types.values()
            if id_type.country_code == country_code.upper()
        ]

    def list_ids_by_region(self, region: IDRegion) -> List[IDType]:
        """List all ID types for a region."""
        return [
            id_type for id_type in self.id_types.values()
            if id_type.region == region
        ]

    def _severity_rank(self, severity: IDSeverity) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {
            IDSeverity.LOW: 1,
            IDSeverity.MODERATE: 2,
            IDSeverity.HIGH: 3,
            IDSeverity.CRITICAL: 4
        }
        return ranks.get(severity, 0)

    def _calculate_risk_score(
        self,
        detected_ids: List[str],
        max_severity: IDSeverity,
        pattern_count: int
    ) -> int:
        """Calculate overall risk score."""
        if not detected_ids:
            return 0

        base_scores = {
            IDSeverity.CRITICAL: 60,
            IDSeverity.HIGH: 40,
            IDSeverity.MODERATE: 25,
            IDSeverity.LOW: 10
        }

        score = base_scores.get(max_severity, 0)

        # Add for multiple IDs detected
        score += (len(detected_ids) - 1) * 10

        # Add for multiple pattern matches
        score += (pattern_count - 1) * 5

        return min(100, score)

    def _generate_recommendations(
        self,
        detected_ids: List[str],
        max_severity: IDSeverity
    ) -> List[str]:
        """Generate security recommendations."""
        if not detected_ids:
            return []

        recommendations = []

        if max_severity == IDSeverity.CRITICAL:
            recommendations.extend([
                "CRITICAL: This message is attempting to steal highly sensitive identification",
                "Never share these ID numbers via SMS, email, or phone calls",
                "Government agencies never request ID numbers this way",
                "Report this to your local cybercrime authority immediately",
                "If you shared any information, contact your bank and relevant authorities"
            ])
        elif max_severity == IDSeverity.HIGH:
            recommendations.extend([
                "WARNING: This message requests sensitive government ID information",
                "Verify the sender through official government channels only",
                "Do not click any links in suspicious messages",
                "Official agencies do not send unsolicited requests for ID"
            ])
        elif max_severity == IDSeverity.MODERATE:
            recommendations.extend([
                "CAUTION: This message mentions identity documents",
                "Verify the legitimacy of any ID-related requests",
                "Contact official agencies directly if in doubt"
            ])

        # Add ID-specific recommendations
        for id_code in detected_ids[:3]:
            id_type = self.id_types.get(id_code)
            if id_type:
                recommendations.append(
                    f"Your {id_type.name} ({id_type.country}) should never be shared via unsolicited messages"
                )

        return recommendations


# Singleton instance for easy import
global_id_detector = GlobalIDDetector()
