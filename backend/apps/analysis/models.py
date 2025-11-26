"""
Analysis Models for Scamlytic API.

Models for storing analysis results and scan history.
"""

import uuid
from django.db import models
from django.conf import settings

from apps.core.models import TimeStampedModel, ThreatType


class AnalysisResult(TimeStampedModel):
    """
    Base model for all analysis results.
    """
    ANALYSIS_TYPES = [
        ('message', 'Message'),
        ('url', 'URL'),
        ('phone', 'Phone'),
        ('profile', 'Profile/Catfish'),
        ('file', 'File'),
    ]

    VERDICT_CHOICES = [
        ('LOW_RISK', 'Low Risk'),
        ('MODERATE_RISK', 'Moderate Risk'),
        ('HIGH_RISK', 'High Risk'),
        ('CRITICAL_RISK', 'Critical Risk'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    # Ownership
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='analyses'
    )
    api_key = models.ForeignKey(
        'users.APIKey',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='analyses'
    )

    # Analysis info
    analysis_type = models.CharField(max_length=20, choices=ANALYSIS_TYPES, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    request_id = models.CharField(max_length=50, unique=True, db_index=True)

    # Input data
    input_content = models.TextField(blank=True, help_text="Original content for analysis")
    input_hash = models.CharField(max_length=64, db_index=True, blank=True)
    context = models.CharField(max_length=50, blank=True)

    # Results
    scam_score = models.IntegerField(default=0, help_text="Score 0-100")
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, default='LOW_RISK')
    threat_type = models.ForeignKey(
        ThreatType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='analyses'
    )
    explanation = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)

    # Detailed results
    signals = models.JSONField(default=list, blank=True)
    analysis_details = models.JSONField(default=dict, blank=True)
    source_results = models.JSONField(default=dict, blank=True, help_text="Results from each integration")

    # Metadata
    processing_time_ms = models.IntegerField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Analysis Result'
        verbose_name_plural = 'Analysis Results'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['analysis_type', 'created_at']),
            models.Index(fields=['verdict', 'created_at']),
            models.Index(fields=['input_hash']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.analysis_type}: {self.request_id} ({self.verdict})"

    def save(self, *args, **kwargs):
        # Generate request_id if not set
        if not self.request_id:
            self.request_id = f"scam_{uuid.uuid4().hex[:16]}"

        # Generate input hash for deduplication
        if self.input_content and not self.input_hash:
            import hashlib
            self.input_hash = hashlib.sha256(self.input_content.encode()).hexdigest()

        super().save(*args, **kwargs)


class MessageAnalysis(TimeStampedModel):
    """
    Detailed message analysis result.
    """
    result = models.OneToOneField(
        AnalysisResult,
        on_delete=models.CASCADE,
        related_name='message_details'
    )

    # Input
    message_content = models.TextField()
    message_context = models.CharField(
        max_length=50,
        blank=True,
        help_text="whatsapp, sms, email, social"
    )
    sender_phone = models.CharField(max_length=20, blank=True)
    sender_email = models.EmailField(blank=True)

    # NLP Analysis
    language_detected = models.CharField(max_length=10, blank=True)
    sentiment_score = models.FloatField(null=True, blank=True)
    urgency_score = models.FloatField(null=True, blank=True)
    manipulation_score = models.FloatField(null=True, blank=True)

    # Pattern matches
    patterns_matched = models.JSONField(default=list, blank=True)
    keywords_found = models.JSONField(default=list, blank=True)
    urls_found = models.JSONField(default=list, blank=True)
    phone_numbers_found = models.JSONField(default=list, blank=True)

    # AI Analysis
    ai_analysis = models.JSONField(default=dict, blank=True)
    ai_confidence = models.FloatField(null=True, blank=True)

    class Meta:
        verbose_name = 'Message Analysis'
        verbose_name_plural = 'Message Analyses'


class URLAnalysis(TimeStampedModel):
    """
    Detailed URL analysis result.
    """
    result = models.OneToOneField(
        AnalysisResult,
        on_delete=models.CASCADE,
        related_name='url_details'
    )

    # Input
    original_url = models.URLField(max_length=2048)
    final_url = models.URLField(max_length=2048, blank=True)
    followed_redirects = models.BooleanField(default=True)
    redirect_chain = models.JSONField(default=list, blank=True)

    # URL Components
    domain = models.CharField(max_length=255, db_index=True)
    tld = models.CharField(max_length=20, blank=True)
    subdomain = models.CharField(max_length=255, blank=True)
    path = models.TextField(blank=True)
    query_params = models.JSONField(default=dict, blank=True)

    # Domain Analysis
    domain_age_days = models.IntegerField(null=True, blank=True)
    registrar = models.CharField(max_length=255, blank=True)
    registration_date = models.DateField(null=True, blank=True)
    whois_data = models.JSONField(default=dict, blank=True)

    # SSL/Security
    has_ssl = models.BooleanField(default=False)
    ssl_valid = models.BooleanField(default=False)
    ssl_issuer = models.CharField(max_length=255, blank=True)
    ssl_expiry = models.DateTimeField(null=True, blank=True)

    # Threat Intelligence
    virustotal_result = models.JSONField(default=dict, blank=True)
    google_safebrowsing_result = models.JSONField(default=dict, blank=True)
    phishtank_result = models.JSONField(default=dict, blank=True)
    urlhaus_result = models.JSONField(default=dict, blank=True)

    # Categorization
    is_shortened = models.BooleanField(default=False)
    shortener_service = models.CharField(max_length=100, blank=True)
    is_ip_address = models.BooleanField(default=False)
    is_homograph = models.BooleanField(default=False)
    homograph_target = models.CharField(max_length=255, blank=True)

    # Page Analysis
    page_title = models.TextField(blank=True)
    page_content_hash = models.CharField(max_length=64, blank=True)
    forms_detected = models.IntegerField(default=0)
    login_form_detected = models.BooleanField(default=False)
    suspicious_elements = models.JSONField(default=list, blank=True)

    class Meta:
        verbose_name = 'URL Analysis'
        verbose_name_plural = 'URL Analyses'
        indexes = [
            models.Index(fields=['domain']),
        ]


class PhoneAnalysis(TimeStampedModel):
    """
    Detailed phone number analysis result.
    """
    result = models.OneToOneField(
        AnalysisResult,
        on_delete=models.CASCADE,
        related_name='phone_details'
    )

    # Input
    phone_number = models.CharField(max_length=20)
    phone_number_e164 = models.CharField(max_length=20, blank=True)

    # Parsed info
    country_code = models.CharField(max_length=5, blank=True)
    national_number = models.CharField(max_length=20, blank=True)
    country_name = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)

    # Carrier info
    carrier_name = models.CharField(max_length=200, blank=True)
    line_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="mobile, landline, voip, toll_free, etc."
    )
    is_voip = models.BooleanField(default=False)
    is_valid = models.BooleanField(default=True)
    is_possible = models.BooleanField(default=True)

    # Reputation
    spam_score = models.IntegerField(null=True, blank=True)
    fraud_score = models.IntegerField(null=True, blank=True)
    report_count = models.IntegerField(default=0)
    last_reported_at = models.DateTimeField(null=True, blank=True)

    # Lookup results
    numverify_result = models.JSONField(default=dict, blank=True)
    ipqualityscore_result = models.JSONField(default=dict, blank=True)
    truecaller_result = models.JSONField(default=dict, blank=True)

    # Database matches
    in_blocklist = models.BooleanField(default=False)
    blocklist_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Phone Analysis'
        verbose_name_plural = 'Phone Analyses'
        indexes = [
            models.Index(fields=['phone_number_e164']),
        ]


class ProfileAnalysis(TimeStampedModel):
    """
    Detailed profile/catfish analysis result.
    """
    result = models.OneToOneField(
        AnalysisResult,
        on_delete=models.CASCADE,
        related_name='profile_details'
    )

    # Input
    profile_url = models.URLField(max_length=2048, blank=True)
    image_url = models.URLField(max_length=2048, blank=True)
    image_hash = models.CharField(max_length=64, blank=True)
    image_perceptual_hash = models.CharField(max_length=64, blank=True)

    # Profile info
    platform = models.CharField(max_length=50, blank=True, help_text="instagram, facebook, etc.")
    username = models.CharField(max_length=100, blank=True)
    display_name = models.CharField(max_length=200, blank=True)
    bio = models.TextField(blank=True)
    follower_count = models.IntegerField(null=True, blank=True)
    following_count = models.IntegerField(null=True, blank=True)
    post_count = models.IntegerField(null=True, blank=True)
    account_created = models.DateField(null=True, blank=True)

    # Image analysis
    has_face = models.BooleanField(default=False)
    face_count = models.IntegerField(default=0)
    image_quality_score = models.FloatField(null=True, blank=True)
    is_stock_photo = models.BooleanField(default=False)
    is_ai_generated = models.BooleanField(default=False)
    ai_detection_confidence = models.FloatField(null=True, blank=True)

    # Reverse image search
    reverse_search_matches = models.JSONField(default=list, blank=True)
    tineye_result = models.JSONField(default=dict, blank=True)
    google_reverse_result = models.JSONField(default=dict, blank=True)

    # Profile analysis
    profile_age_days = models.IntegerField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    engagement_rate = models.FloatField(null=True, blank=True)
    profile_completeness = models.FloatField(null=True, blank=True)
    suspicious_indicators = models.JSONField(default=list, blank=True)

    # Cross-platform detection
    similar_profiles_found = models.JSONField(default=list, blank=True)
    known_scammer_match = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Profile Analysis'
        verbose_name_plural = 'Profile Analyses'
        indexes = [
            models.Index(fields=['image_hash']),
            models.Index(fields=['image_perceptual_hash']),
        ]


class ScamReport(TimeStampedModel):
    """
    User-submitted scam reports for crowdsourced intelligence.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('duplicate', 'Duplicate'),
    ]

    # Reporter
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scam_reports'
    )
    reporter_email = models.EmailField(blank=True)

    # Related analysis
    analysis = models.ForeignKey(
        AnalysisResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scam_reports_filed'
    )

    # Report content
    report_type = models.CharField(max_length=20, choices=AnalysisResult.ANALYSIS_TYPES)
    content = models.TextField(help_text="Reported content (URL, phone, message)")
    description = models.TextField(blank=True, help_text="User description of the scam")
    threat_type = models.ForeignKey(
        ThreatType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # Metadata
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_reports'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)

    # Evidence
    evidence_urls = models.JSONField(default=list, blank=True)
    screenshots = models.JSONField(default=list, blank=True)

    class Meta:
        verbose_name = 'Scam Report'
        verbose_name_plural = 'Scam Reports'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['report_type', 'status']),
        ]

    def __str__(self):
        return f"{self.report_type} Report: {self.id}"
