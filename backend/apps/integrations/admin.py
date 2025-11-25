"""
Admin configuration for Integrations models.
"""

from django.contrib import admin
from .models import Webhook, WebhookDelivery, ExternalIntegration, IntegrationHealth


@admin.register(Webhook)
class WebhookAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'url', 'is_active', 'total_deliveries', 'successful_deliveries']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'url', 'user__email']
    readonly_fields = ['total_deliveries', 'successful_deliveries', 'failed_deliveries', 'created_at']


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ['webhook', 'event', 'status', 'response_status_code', 'duration_ms', 'created_at']
    list_filter = ['status', 'event', 'created_at']
    search_fields = ['webhook__name', 'event']
    readonly_fields = ['created_at']


@admin.register(ExternalIntegration)
class ExternalIntegrationAdmin(admin.ModelAdmin):
    list_display = ['name', 'integration_type', 'user', 'is_active', 'last_sync_at']
    list_filter = ['integration_type', 'is_active']
    search_fields = ['name', 'user__email']
    readonly_fields = ['last_sync_at', 'created_at']


@admin.register(IntegrationHealth)
class IntegrationHealthAdmin(admin.ModelAdmin):
    list_display = ['service_name', 'display_name', 'is_healthy', 'response_time_ms', 'last_check_at']
    list_filter = ['is_healthy']
    readonly_fields = ['last_check_at']
