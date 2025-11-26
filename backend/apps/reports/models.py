"""
Report Models for Scamlytic API.

Models for generating and storing analysis reports.
"""

import uuid
from django.db import models
from django.conf import settings

from apps.core.models import TimeStampedModel


class Report(TimeStampedModel):
    """
    Generated analysis reports.
    """
    FORMAT_CHOICES = [
        ('json', 'JSON'),
        ('pdf', 'PDF'),
        ('html', 'HTML'),
        ('csv', 'CSV'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reports'
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)

    # Report configuration
    report_type = models.CharField(
        max_length=50,
        choices=[
            ('single_analysis', 'Single Analysis'),
            ('batch_analysis', 'Batch Analysis'),
            ('daily_summary', 'Daily Summary'),
            ('weekly_summary', 'Weekly Summary'),
            ('monthly_summary', 'Monthly Summary'),
            ('threat_report', 'Threat Intelligence Report'),
        ],
        default='single_analysis'
    )
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='json')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Related analyses
    analyses = models.ManyToManyField(
        'analysis.AnalysisResult',
        related_name='generated_reports',
        blank=True
    )

    # Date range for summary reports
    date_from = models.DateField(null=True, blank=True)
    date_to = models.DateField(null=True, blank=True)

    # Generated content
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.IntegerField(null=True, blank=True)
    content = models.JSONField(default=dict, blank=True)

    # Sharing
    is_public = models.BooleanField(default=False)
    share_token = models.CharField(max_length=64, blank=True, unique=True, null=True)
    share_expires_at = models.DateTimeField(null=True, blank=True)

    # Statistics
    view_count = models.IntegerField(default=0)
    download_count = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'Report'
        verbose_name_plural = 'Reports'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.report_type})"

    def generate_share_token(self):
        """Generate a unique share token."""
        import secrets
        self.share_token = secrets.token_urlsafe(48)
        self.save(update_fields=['share_token'])
        return self.share_token


class ReportTemplate(TimeStampedModel):
    """
    Reusable report templates.
    """
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    report_type = models.CharField(max_length=50)
    template_content = models.TextField(help_text="HTML/Jinja2 template")
    css_styles = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Report Template'
        verbose_name_plural = 'Report Templates'

    def __str__(self):
        return self.name


class ScheduledReport(TimeStampedModel):
    """
    Scheduled automatic report generation.
    """
    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scheduled_reports'
    )
    name = models.CharField(max_length=200)
    report_type = models.CharField(max_length=50)
    format = models.CharField(max_length=10, default='pdf')
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)

    # Schedule
    is_active = models.BooleanField(default=True)
    next_run_at = models.DateTimeField()
    last_run_at = models.DateTimeField(null=True, blank=True)

    # Delivery
    email_enabled = models.BooleanField(default=True)
    email_recipients = models.JSONField(default=list, blank=True)
    webhook_enabled = models.BooleanField(default=False)
    webhook_url = models.URLField(blank=True)

    class Meta:
        verbose_name = 'Scheduled Report'
        verbose_name_plural = 'Scheduled Reports'

    def __str__(self):
        return f"{self.name} ({self.frequency})"
