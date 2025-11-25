"""
Integration Models for Scamlytic API.

Models for webhooks, external integrations, and third-party services.
"""

import uuid
from django.db import models
from django.conf import settings

from apps.core.models import TimeStampedModel


class Webhook(TimeStampedModel):
    """
    Webhook configuration for user notifications.
    """
    EVENT_CHOICES = [
        ('analysis.completed', 'Analysis Completed'),
        ('analysis.high_risk', 'High Risk Detected'),
        ('analysis.critical', 'Critical Risk Detected'),
        ('report.generated', 'Report Generated'),
        ('quota.warning', 'Quota Warning'),
        ('quota.exceeded', 'Quota Exceeded'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='webhooks'
    )
    name = models.CharField(max_length=100)
    url = models.URLField(max_length=500)
    secret = models.CharField(max_length=100, blank=True)
    events = models.JSONField(default=list, help_text="List of events to subscribe to")

    # Configuration
    is_active = models.BooleanField(default=True)
    verify_ssl = models.BooleanField(default=True)
    timeout_seconds = models.IntegerField(default=30)
    retry_count = models.IntegerField(default=3)

    # Statistics
    total_deliveries = models.IntegerField(default=0)
    successful_deliveries = models.IntegerField(default=0)
    failed_deliveries = models.IntegerField(default=0)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_failure_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Webhook'
        verbose_name_plural = 'Webhooks'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.user.email})"


class WebhookDelivery(TimeStampedModel):
    """
    Webhook delivery log.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
        ('retrying', 'Retrying'),
    ]

    webhook = models.ForeignKey(
        Webhook,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    event = models.CharField(max_length=50)
    payload = models.JSONField(default=dict)

    # Delivery info
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    response_status_code = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    duration_ms = models.IntegerField(null=True, blank=True)

    # Retry info
    attempt_count = models.IntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Webhook Delivery'
        verbose_name_plural = 'Webhook Deliveries'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.webhook.name} - {self.event} ({self.status})"


class ExternalIntegration(TimeStampedModel):
    """
    External service integrations (Slack, Discord, etc.)
    """
    INTEGRATION_TYPES = [
        ('slack', 'Slack'),
        ('discord', 'Discord'),
        ('telegram', 'Telegram'),
        ('email', 'Email'),
        ('teams', 'Microsoft Teams'),
        ('zapier', 'Zapier'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='integrations'
    )
    integration_type = models.CharField(max_length=20, choices=INTEGRATION_TYPES)
    name = models.CharField(max_length=100)

    # Configuration (encrypted in production)
    config = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)

    # OAuth tokens (if applicable)
    access_token = models.CharField(max_length=500, blank=True)
    refresh_token = models.CharField(max_length=500, blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)

    # Status
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        verbose_name = 'External Integration'
        verbose_name_plural = 'External Integrations'
        unique_together = ['user', 'integration_type', 'name']

    def __str__(self):
        return f"{self.name} ({self.integration_type})"


class IntegrationHealth(TimeStampedModel):
    """
    Health status of third-party service integrations.
    """
    service_name = models.CharField(max_length=50, unique=True)
    display_name = models.CharField(max_length=100)
    is_healthy = models.BooleanField(default=True)
    last_check_at = models.DateTimeField(auto_now=True)
    response_time_ms = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    consecutive_failures = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'Integration Health'
        verbose_name_plural = 'Integration Health'

    def __str__(self):
        status = "Healthy" if self.is_healthy else "Unhealthy"
        return f"{self.display_name}: {status}"
