"""
Admin configuration for Analysis models.
"""

from django.contrib import admin
from .models import (
    AnalysisResult, MessageAnalysis, URLAnalysis,
    PhoneAnalysis, ProfileAnalysis, ScamReport
)


@admin.register(AnalysisResult)
class AnalysisResultAdmin(admin.ModelAdmin):
    list_display = [
        'request_id', 'analysis_type', 'scam_score', 'verdict',
        'threat_type', 'user', 'created_at'
    ]
    list_filter = ['analysis_type', 'verdict', 'status', 'created_at']
    search_fields = ['request_id', 'user__email', 'input_content']
    readonly_fields = ['id', 'request_id', 'input_hash', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('request_id', 'analysis_type', 'status', 'user', 'api_key')
        }),
        ('Results', {
            'fields': ('scam_score', 'verdict', 'threat_type', 'explanation', 'recommended_action')
        }),
        ('Details', {
            'fields': ('signals', 'analysis_details', 'source_results'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('processing_time_ms', 'ip_address', 'user_agent', 'created_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(MessageAnalysis)
class MessageAnalysisAdmin(admin.ModelAdmin):
    list_display = ['result', 'message_context', 'language_detected', 'urgency_score']
    list_filter = ['message_context', 'language_detected']
    search_fields = ['message_content', 'sender_phone', 'sender_email']


@admin.register(URLAnalysis)
class URLAnalysisAdmin(admin.ModelAdmin):
    list_display = ['result', 'domain', 'is_shortened', 'has_ssl', 'domain_age_days']
    list_filter = ['is_shortened', 'has_ssl', 'ssl_valid']
    search_fields = ['original_url', 'domain']


@admin.register(PhoneAnalysis)
class PhoneAnalysisAdmin(admin.ModelAdmin):
    list_display = ['result', 'phone_number', 'country_name', 'carrier_name', 'is_voip', 'spam_score']
    list_filter = ['is_voip', 'is_valid', 'country_code', 'in_blocklist']
    search_fields = ['phone_number', 'phone_number_e164', 'carrier_name']


@admin.register(ProfileAnalysis)
class ProfileAnalysisAdmin(admin.ModelAdmin):
    list_display = ['result', 'platform', 'username', 'has_face', 'is_ai_generated', 'is_stock_photo']
    list_filter = ['platform', 'has_face', 'is_ai_generated', 'is_stock_photo', 'known_scammer_match']
    search_fields = ['profile_url', 'username', 'display_name']


@admin.register(ScamReport)
class ScamReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'report_type', 'status', 'reporter', 'created_at']
    list_filter = ['report_type', 'status', 'threat_type', 'created_at']
    search_fields = ['content', 'description', 'reporter__email']
    readonly_fields = ['created_at', 'updated_at']

    actions = ['mark_verified', 'mark_rejected']

    def mark_verified(self, request, queryset):
        queryset.update(status='verified')
    mark_verified.short_description = "Mark selected reports as verified"

    def mark_rejected(self, request, queryset):
        queryset.update(status='rejected')
    mark_rejected.short_description = "Mark selected reports as rejected"
