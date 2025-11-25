"""
Serializers for Reports API.
"""

from rest_framework import serializers
from .models import Report, ScheduledReport


class ReportSerializer(serializers.ModelSerializer):
    """Serializer for reports."""

    class Meta:
        model = Report
        fields = [
            'id', 'name', 'description', 'report_type', 'format',
            'status', 'date_from', 'date_to', 'file_size',
            'is_public', 'share_token', 'share_expires_at',
            'view_count', 'download_count', 'created_at'
        ]
        read_only_fields = [
            'id', 'status', 'file_size', 'share_token',
            'view_count', 'download_count', 'created_at'
        ]


class ReportCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating reports."""
    analysis_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        write_only=True
    )

    class Meta:
        model = Report
        fields = [
            'name', 'description', 'report_type', 'format',
            'date_from', 'date_to', 'analysis_ids', 'is_public'
        ]

    def create(self, validated_data):
        analysis_ids = validated_data.pop('analysis_ids', [])
        report = Report.objects.create(**validated_data)

        if analysis_ids:
            from apps.analysis.models import AnalysisResult
            analyses = AnalysisResult.objects.filter(
                id__in=analysis_ids,
                user=validated_data.get('user')
            )
            report.analyses.set(analyses)

        return report


class ReportContentSerializer(serializers.Serializer):
    """Serializer for report content."""
    summary = serializers.DictField()
    analyses = serializers.ListField(child=serializers.DictField())
    statistics = serializers.DictField()
    recommendations = serializers.ListField(child=serializers.CharField())
    generated_at = serializers.DateTimeField()


class ScheduledReportSerializer(serializers.ModelSerializer):
    """Serializer for scheduled reports."""

    class Meta:
        model = ScheduledReport
        fields = [
            'id', 'name', 'report_type', 'format', 'frequency',
            'is_active', 'next_run_at', 'last_run_at',
            'email_enabled', 'email_recipients',
            'webhook_enabled', 'webhook_url',
            'created_at'
        ]
        read_only_fields = ['id', 'last_run_at', 'created_at']
