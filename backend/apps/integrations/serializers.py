"""
Serializers for Integrations API.
"""

from rest_framework import serializers
from .models import Webhook, WebhookDelivery, ExternalIntegration, IntegrationHealth


class WebhookSerializer(serializers.ModelSerializer):
    """Serializer for webhooks."""
    success_rate = serializers.SerializerMethodField()

    class Meta:
        model = Webhook
        fields = [
            'id', 'name', 'url', 'events', 'is_active',
            'verify_ssl', 'timeout_seconds', 'retry_count',
            'total_deliveries', 'successful_deliveries', 'failed_deliveries',
            'success_rate', 'last_triggered_at', 'last_success_at',
            'last_failure_at', 'last_failure_reason', 'created_at'
        ]
        read_only_fields = [
            'id', 'total_deliveries', 'successful_deliveries', 'failed_deliveries',
            'last_triggered_at', 'last_success_at', 'last_failure_at',
            'last_failure_reason', 'created_at'
        ]

    def get_success_rate(self, obj):
        if obj.total_deliveries == 0:
            return 100.0
        return round((obj.successful_deliveries / obj.total_deliveries) * 100, 1)


class WebhookCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating webhooks."""

    class Meta:
        model = Webhook
        fields = [
            'name', 'url', 'secret', 'events', 'is_active',
            'verify_ssl', 'timeout_seconds', 'retry_count'
        ]


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for webhook deliveries."""

    class Meta:
        model = WebhookDelivery
        fields = [
            'id', 'event', 'status', 'response_status_code',
            'duration_ms', 'attempt_count', 'error_message', 'created_at'
        ]


class ExternalIntegrationSerializer(serializers.ModelSerializer):
    """Serializer for external integrations."""

    class Meta:
        model = ExternalIntegration
        fields = [
            'id', 'integration_type', 'name', 'config', 'is_active',
            'last_sync_at', 'last_error', 'created_at'
        ]
        read_only_fields = ['id', 'last_sync_at', 'last_error', 'created_at']


class IntegrationHealthSerializer(serializers.ModelSerializer):
    """Serializer for integration health."""

    class Meta:
        model = IntegrationHealth
        fields = [
            'service_name', 'display_name', 'is_healthy',
            'last_check_at', 'response_time_ms', 'error_message'
        ]
