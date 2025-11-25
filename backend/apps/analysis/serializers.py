"""
Serializers for Analysis API.
"""

from rest_framework import serializers
from django.conf import settings

from .models import AnalysisResult, MessageAnalysis, URLAnalysis, PhoneAnalysis, ProfileAnalysis, ScamReport


class MessageAnalysisRequestSerializer(serializers.Serializer):
    """Request serializer for message analysis."""
    content = serializers.CharField(
        max_length=settings.MAX_MESSAGE_LENGTH,
        required=True,
        help_text="Message content to analyze (max 5000 characters)"
    )
    context = serializers.ChoiceField(
        choices=['whatsapp', 'sms', 'email', 'social', 'unknown'],
        required=False,
        default='unknown',
        help_text="Message context/platform"
    )
    sender_phone = serializers.CharField(
        max_length=20,
        required=False,
        allow_blank=True,
        help_text="Sender's phone number (optional)"
    )
    sender_email = serializers.EmailField(
        required=False,
        allow_blank=True,
        help_text="Sender's email address (optional)"
    )


class URLAnalysisRequestSerializer(serializers.Serializer):
    """Request serializer for URL analysis."""
    url = serializers.URLField(
        max_length=2048,
        required=True,
        help_text="URL to analyze"
    )
    follow_redirects = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Whether to follow redirects"
    )


class PhoneAnalysisRequestSerializer(serializers.Serializer):
    """Request serializer for phone analysis."""
    phone = serializers.CharField(
        max_length=20,
        required=True,
        help_text="Phone number in E.164 format (+234...)"
    )
    region = serializers.CharField(
        max_length=2,
        required=False,
        default='US',
        help_text="Default region code (e.g., US, NG, GB)"
    )


class ProfileAnalysisRequestSerializer(serializers.Serializer):
    """Request serializer for profile/catfish analysis."""
    image_url = serializers.URLField(
        max_length=2048,
        required=False,
        allow_blank=True,
        help_text="URL of the profile image"
    )
    image_base64 = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Base64 encoded image data"
    )
    profile_url = serializers.URLField(
        max_length=2048,
        required=False,
        allow_blank=True,
        help_text="Social media profile URL"
    )

    def validate(self, attrs):
        """Ensure at least one input is provided."""
        if not any([
            attrs.get('image_url'),
            attrs.get('image_base64'),
            attrs.get('profile_url')
        ]):
            raise serializers.ValidationError(
                "At least one of image_url, image_base64, or profile_url is required"
            )
        return attrs


class AnalysisResponseSerializer(serializers.Serializer):
    """Response serializer for all analysis endpoints."""
    scam_score = serializers.IntegerField(
        min_value=0,
        max_value=100,
        help_text="Risk score from 0-100"
    )
    verdict = serializers.ChoiceField(
        choices=['LOW_RISK', 'MODERATE_RISK', 'HIGH_RISK', 'CRITICAL_RISK'],
        help_text="Risk verdict"
    )
    threat_type = serializers.CharField(help_text="Detected threat type code")
    explanation = serializers.CharField(help_text="Human-readable explanation")
    recommended_action = serializers.CharField(help_text="Recommended user action")
    signals = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of detected indicators"
    )
    request_id = serializers.CharField(help_text="Unique request identifier")
    confidence = serializers.FloatField(
        min_value=0,
        max_value=1,
        help_text="Confidence score 0-1"
    )


class MessageAnalysisResponseSerializer(AnalysisResponseSerializer):
    """Response serializer for message analysis."""
    text_analysis = serializers.DictField(required=False)
    pattern_analysis = serializers.DictField(required=False)
    llm_analysis = serializers.DictField(required=False)
    urls_found = serializers.ListField(
        child=serializers.DictField(),
        required=False
    )
    phones_found = serializers.ListField(
        child=serializers.DictField(),
        required=False
    )
    processing_time_ms = serializers.IntegerField()


class URLAnalysisResponseSerializer(AnalysisResponseSerializer):
    """Response serializer for URL analysis."""
    url = serializers.URLField()
    final_url = serializers.URLField(required=False)
    domain = serializers.CharField()
    is_shortened = serializers.BooleanField()
    is_https = serializers.BooleanField()
    domain_age_days = serializers.IntegerField(allow_null=True, required=False)
    ssl_info = serializers.DictField(required=False)
    threat_intel = serializers.DictField(required=False)
    processing_time_ms = serializers.IntegerField()


class PhoneAnalysisResponseSerializer(AnalysisResponseSerializer):
    """Response serializer for phone analysis."""
    phone_number = serializers.CharField()
    e164_format = serializers.CharField()
    country_code = serializers.CharField()
    country_name = serializers.CharField()
    carrier = serializers.CharField(allow_blank=True)
    line_type = serializers.CharField()
    is_valid = serializers.BooleanField()
    is_voip = serializers.BooleanField()
    fraud_score = serializers.IntegerField()
    in_blocklist = serializers.BooleanField()
    processing_time_ms = serializers.IntegerField()


class ProfileAnalysisResponseSerializer(AnalysisResponseSerializer):
    """Response serializer for profile/catfish analysis."""
    has_face = serializers.BooleanField()
    face_count = serializers.IntegerField()
    is_ai_generated = serializers.BooleanField()
    ai_detection_confidence = serializers.FloatField()
    is_stock_photo = serializers.BooleanField()
    image_found_elsewhere = serializers.BooleanField()
    match_count = serializers.IntegerField()
    reverse_search_matches = serializers.ListField(
        child=serializers.DictField(),
        required=False
    )
    processing_time_ms = serializers.IntegerField()


class AnalysisResultSerializer(serializers.ModelSerializer):
    """Serializer for AnalysisResult model."""

    class Meta:
        model = AnalysisResult
        fields = [
            'id', 'request_id', 'analysis_type', 'status',
            'scam_score', 'verdict', 'threat_type',
            'explanation', 'recommended_action', 'signals',
            'processing_time_ms', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class AnalysisHistorySerializer(serializers.ModelSerializer):
    """Serializer for analysis history list."""

    class Meta:
        model = AnalysisResult
        fields = [
            'id', 'request_id', 'analysis_type',
            'scam_score', 'verdict', 'threat_type',
            'created_at'
        ]


class ScamReportSerializer(serializers.ModelSerializer):
    """Serializer for scam reports."""

    class Meta:
        model = ScamReport
        fields = [
            'id', 'report_type', 'content', 'description',
            'threat_type', 'status', 'evidence_urls',
            'created_at'
        ]
        read_only_fields = ['id', 'status', 'created_at']


class ScamReportCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating scam reports."""

    class Meta:
        model = ScamReport
        fields = [
            'report_type', 'content', 'description',
            'threat_type', 'evidence_urls', 'reporter_email'
        ]

    def create(self, validated_data):
        # Add reporter if authenticated
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['reporter'] = request.user
        return super().create(validated_data)


class BatchAnalysisRequestSerializer(serializers.Serializer):
    """Request serializer for batch analysis."""
    items = serializers.ListField(
        child=serializers.DictField(),
        max_length=100,
        help_text="List of items to analyze (max 100)"
    )
    analysis_type = serializers.ChoiceField(
        choices=['message', 'url', 'phone'],
        required=True,
        help_text="Type of analysis to perform"
    )
