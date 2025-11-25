"""
Views for Reports API.
"""

import logging
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Report, ScheduledReport
from .serializers import (
    ReportSerializer, ReportCreateSerializer,
    ScheduledReportSerializer
)
from .services import ReportGeneratorService

logger = logging.getLogger('scamlytic.reports')


class ReportListCreateView(generics.ListCreateAPIView):
    """
    List and create reports.

    GET /v1/reports/
    POST /v1/reports/
    """
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ReportCreateSerializer
        return ReportSerializer

    def get_queryset(self):
        return Report.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create report
        report = serializer.save(user=request.user)

        # Generate report content
        generator = ReportGeneratorService()
        try:
            generator.generate(report)
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            report.status = 'failed'
            report.save()

        return Response(
            ReportSerializer(report).data,
            status=status.HTTP_201_CREATED
        )


class ReportDetailView(generics.RetrieveDestroyAPIView):
    """
    Get or delete a report.

    GET/DELETE /v1/reports/{id}/
    """
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(user=self.request.user)


class ReportDownloadView(views.APIView):
    """
    Download a report.

    GET /v1/reports/{id}/download/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            report = Report.objects.get(pk=pk, user=request.user)
        except Report.DoesNotExist:
            return Response(
                {'error': 'Report not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        if report.status != 'completed':
            return Response(
                {'error': 'Report not ready'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Increment download count
        report.download_count += 1
        report.save(update_fields=['download_count'])

        # Return based on format
        if report.format == 'json':
            return Response(report.content)
        else:
            # For PDF/HTML, return file URL or content
            return Response({
                'download_url': report.file_path,
                'format': report.format,
            })


class SharedReportView(views.APIView):
    """
    View a shared report (public access).

    GET /v1/reports/shared/{token}/
    """
    permission_classes = []
    authentication_classes = []

    def get(self, request, token):
        try:
            report = Report.objects.get(
                share_token=token,
                is_public=True
            )
        except Report.DoesNotExist:
            return Response(
                {'error': 'Report not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check expiration
        from django.utils import timezone
        if report.share_expires_at and report.share_expires_at < timezone.now():
            return Response(
                {'error': 'Share link has expired'},
                status=status.HTTP_410_GONE
            )

        # Increment view count
        report.view_count += 1
        report.save(update_fields=['view_count'])

        return Response(ReportSerializer(report).data)


class ScheduledReportListCreateView(generics.ListCreateAPIView):
    """
    List and create scheduled reports.

    GET/POST /v1/reports/scheduled/
    """
    serializer_class = ScheduledReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ScheduledReport.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ScheduledReportDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Get, update, or delete a scheduled report.

    GET/PUT/DELETE /v1/reports/scheduled/{id}/
    """
    serializer_class = ScheduledReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ScheduledReport.objects.filter(user=self.request.user)
