"""
Views for Analysis API endpoints.
"""

import logging
import time
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.conf import settings

from apps.core.exceptions import QuotaExceededError, ValidationError
from apps.users.models import APIKey

from .models import AnalysisResult, ScamReport
from .serializers import (
    MessageAnalysisRequestSerializer, MessageAnalysisResponseSerializer,
    URLAnalysisRequestSerializer, URLAnalysisResponseSerializer,
    PhoneAnalysisRequestSerializer, PhoneAnalysisResponseSerializer,
    ProfileAnalysisRequestSerializer, ProfileAnalysisResponseSerializer,
    AnalysisResultSerializer, AnalysisHistorySerializer,
    ScamReportSerializer, ScamReportCreateSerializer,
    BatchAnalysisRequestSerializer
)

from services.message_analyzer import MessageAnalyzerService
from services.url_analyzer import URLAnalyzerService
from services.phone_analyzer import PhoneAnalyzerService
from services.image_analyzer import ImageAnalyzerService

logger = logging.getLogger('scamlytic.analysis')


class BaseAnalysisView(views.APIView):
    """Base view for analysis endpoints with common functionality."""

    def check_quota(self, request):
        """Check if user has remaining quota."""
        user = request.user
        if user.is_authenticated:
            if not user.can_make_request():
                raise QuotaExceededError(
                    message=f"Daily quota exceeded ({user.daily_limit} requests/day). "
                            "Upgrade your plan for more requests.",
                    details={
                        'plan': user.plan,
                        'daily_limit': user.daily_limit,
                        'daily_used': user.daily_request_count,
                    }
                )

    def record_usage(self, request):
        """Record API usage."""
        user = request.user
        if user.is_authenticated:
            user.increment_request_count()

    def save_analysis_result(self, request, result, analysis_type):
        """Save analysis result to database."""
        try:
            api_key = None
            if hasattr(request, 'auth') and isinstance(request.auth, APIKey):
                api_key = request.auth

            analysis = AnalysisResult.objects.create(
                user=request.user if request.user.is_authenticated else None,
                api_key=api_key,
                analysis_type=analysis_type,
                status='completed',
                request_id=result.request_id,
                scam_score=result.scam_score,
                verdict=result.verdict,
                explanation=result.explanation,
                recommended_action=result.recommended_action,
                signals=result.signals,
                processing_time_ms=result.processing_time_ms,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )
            return analysis
        except Exception as e:
            logger.error(f"Failed to save analysis result: {e}")
            return None

    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class MessageAnalysisView(BaseAnalysisView):
    """
    Analyze text messages for scam indicators.

    POST /v1/analyze/message/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Validate request
        serializer = MessageAnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check quota
        self.check_quota(request)

        # Perform analysis
        analyzer = MessageAnalyzerService()
        result = analyzer.analyze(
            content=serializer.validated_data['content'],
            context=serializer.validated_data.get('context', 'unknown'),
            sender_phone=serializer.validated_data.get('sender_phone'),
            sender_email=serializer.validated_data.get('sender_email'),
        )

        # Record usage
        self.record_usage(request)

        # Save result
        self.save_analysis_result(request, result, 'message')

        # Build response
        response_data = {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'explanation': result.explanation,
            'recommended_action': result.recommended_action,
            'signals': result.signals,
            'request_id': result.request_id,
            'confidence': result.confidence,
            'text_analysis': result.text_analysis,
            'pattern_analysis': result.pattern_analysis,
            'llm_analysis': result.llm_analysis,
            'urls_found': result.urls_analysis,
            'phones_found': result.phones_analysis,
            'processing_time_ms': result.processing_time_ms,
        }

        return Response(response_data)


class URLAnalysisView(BaseAnalysisView):
    """
    Analyze URLs for phishing and malware.

    POST /v1/analyze/url/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Validate request
        serializer = URLAnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check quota
        self.check_quota(request)

        # Perform analysis
        analyzer = URLAnalyzerService()
        result = analyzer.analyze(
            url=serializer.validated_data['url'],
            follow_redirects=serializer.validated_data.get('follow_redirects', True),
        )

        # Record usage
        self.record_usage(request)

        # Save result
        self.save_analysis_result(request, result, 'url')

        # Build response
        response_data = {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'explanation': result.explanation,
            'recommended_action': result.recommended_action,
            'signals': result.signals,
            'request_id': result.request_id,
            'confidence': result.confidence,
            'url': result.url,
            'final_url': result.final_url,
            'domain': result.domain,
            'is_shortened': result.is_shortened,
            'is_https': result.is_https,
            'domain_age_days': result.domain_age_days,
            'ssl_info': result.ssl_info,
            'threat_intel': result.threat_intel,
            'processing_time_ms': result.processing_time_ms,
        }

        return Response(response_data)


class PhoneAnalysisView(BaseAnalysisView):
    """
    Analyze phone numbers for scam indicators.

    POST /v1/analyze/phone/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Validate request
        serializer = PhoneAnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check quota
        self.check_quota(request)

        # Perform analysis
        analyzer = PhoneAnalyzerService()
        result = analyzer.analyze(
            phone=serializer.validated_data['phone'],
            default_region=serializer.validated_data.get('region', 'US'),
        )

        # Record usage
        self.record_usage(request)

        # Save result
        self.save_analysis_result(request, result, 'phone')

        # Build response
        response_data = {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'explanation': result.explanation,
            'recommended_action': result.recommended_action,
            'signals': result.signals,
            'request_id': result.request_id,
            'confidence': result.confidence,
            'phone_number': result.phone_number,
            'e164_format': result.e164_format,
            'country_code': result.country_code,
            'country_name': result.country_name,
            'carrier': result.carrier,
            'line_type': result.line_type,
            'is_valid': result.is_valid,
            'is_voip': result.is_voip,
            'fraud_score': result.fraud_score,
            'in_blocklist': result.in_blocklist,
            'processing_time_ms': result.processing_time_ms,
        }

        return Response(response_data)


class ProfileAnalysisView(BaseAnalysisView):
    """
    Analyze profiles for catfish detection.

    POST /v1/analyze/profile/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Validate request
        serializer = ProfileAnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check quota
        self.check_quota(request)

        # Perform analysis
        analyzer = ImageAnalyzerService()
        result = analyzer.analyze(
            image_url=serializer.validated_data.get('image_url'),
            image_base64=serializer.validated_data.get('image_base64'),
            profile_url=serializer.validated_data.get('profile_url'),
        )

        # Record usage
        self.record_usage(request)

        # Save result
        self.save_analysis_result(request, result, 'profile')

        # Build response
        response_data = {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'threat_type': result.threat_type,
            'explanation': result.explanation,
            'recommended_action': result.recommended_action,
            'signals': result.signals,
            'request_id': result.request_id,
            'confidence': result.confidence,
            'has_face': result.has_face,
            'face_count': result.face_count,
            'is_ai_generated': result.is_ai_generated,
            'ai_detection_confidence': result.ai_detection_confidence,
            'is_stock_photo': result.is_stock_photo,
            'image_found_elsewhere': result.image_found_elsewhere,
            'match_count': result.match_count,
            'reverse_search_matches': result.reverse_search_matches,
            'processing_time_ms': result.processing_time_ms,
        }

        return Response(response_data)


class AnalysisHistoryView(generics.ListAPIView):
    """
    List user's analysis history.

    GET /v1/analyze/history/
    """
    serializer_class = AnalysisHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        queryset = AnalysisResult.objects.filter(user=user)

        # Filter by type
        analysis_type = self.request.query_params.get('type')
        if analysis_type:
            queryset = queryset.filter(analysis_type=analysis_type)

        # Filter by verdict
        verdict = self.request.query_params.get('verdict')
        if verdict:
            queryset = queryset.filter(verdict=verdict)

        return queryset[:100]  # Limit to 100


class AnalysisDetailView(generics.RetrieveAPIView):
    """
    Get analysis details by request ID.

    GET /v1/analyze/{request_id}/
    """
    serializer_class = AnalysisResultSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'request_id'

    def get_queryset(self):
        return AnalysisResult.objects.filter(user=self.request.user)


class ScamReportListCreateView(generics.ListCreateAPIView):
    """
    List and create scam reports.

    GET/POST /v1/analyze/reports/
    """
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ScamReportCreateSerializer
        return ScamReportSerializer

    def get_queryset(self):
        if self.request.user.is_staff:
            return ScamReport.objects.all()
        return ScamReport.objects.filter(reporter=self.request.user)


class QuickScanView(views.APIView):
    """
    Quick scan endpoint for basic analysis.

    POST /v1/analyze/quick/
    """
    permission_classes = [AllowAny]

    def post(self, request):
        scan_type = request.data.get('type', 'message')
        content = request.data.get('content', '')

        if not content:
            return Response(
                {'error': 'Content is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Rate limit for anonymous users
        if not request.user.is_authenticated:
            from django.core.cache import cache
            ip = self._get_client_ip(request)
            cache_key = f"quick_scan:{ip}"
            count = cache.get(cache_key, 0)
            if count >= 5:  # 5 quick scans per hour for anonymous
                return Response(
                    {'error': 'Rate limit exceeded. Please sign up for more scans.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            cache.set(cache_key, count + 1, timeout=3600)

        # Perform quick scan based on type
        if scan_type == 'message':
            analyzer = MessageAnalyzerService()
            result = analyzer.quick_scan(content)
        elif scan_type == 'url':
            analyzer = URLAnalyzerService()
            result = analyzer.quick_scan(content)
        elif scan_type == 'phone':
            analyzer = PhoneAnalyzerService()
            result = analyzer.quick_scan(content)
        else:
            return Response(
                {'error': 'Invalid scan type'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(result)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class BatchAnalysisView(BaseAnalysisView):
    """
    Batch analysis for multiple items.

    POST /v1/analyze/batch/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = BatchAnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        items = serializer.validated_data['items']
        analysis_type = serializer.validated_data['analysis_type']

        # Check if user has enough quota
        user = request.user
        if user.remaining_requests < len(items):
            raise QuotaExceededError(
                message=f"Not enough quota. You have {user.remaining_requests} requests remaining.",
                details={
                    'requested': len(items),
                    'remaining': user.remaining_requests,
                }
            )

        # Perform batch analysis
        if analysis_type == 'message':
            analyzer = MessageAnalyzerService()
            results = analyzer.batch_analyze(
                [{'content': item.get('content', ''), 'context': item.get('context', 'unknown')}
                 for item in items]
            )
        elif analysis_type == 'url':
            analyzer = URLAnalyzerService()
            results = analyzer.batch_analyze([item.get('url', '') for item in items])
        elif analysis_type == 'phone':
            analyzer = PhoneAnalyzerService()
            results = analyzer.batch_analyze([item.get('phone', '') for item in items])
        else:
            return Response(
                {'error': 'Invalid analysis type'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Record usage for each item
        for _ in items:
            self.record_usage(request)

        return Response({
            'results': results,
            'count': len(results),
        })
