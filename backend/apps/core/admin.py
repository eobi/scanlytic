"""
Admin configuration for Core models.
"""

from django.contrib import admin
from .models import ThreatType, SignalType, BlockedDomain, BlockedPhoneNumber, ScamPattern, SystemConfig


@admin.register(ThreatType)
class ThreatTypeAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'severity', 'is_active', 'created_at']
    list_filter = ['severity', 'is_active']
    search_fields = ['code', 'name', 'description']


@admin.register(SignalType)
class SignalTypeAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'severity', 'weight', 'is_active']
    list_filter = ['severity', 'is_active']
    search_fields = ['code', 'name', 'description']


@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'threat_type', 'source', 'confidence', 'report_count', 'is_active']
    list_filter = ['threat_type', 'source', 'is_active']
    search_fields = ['domain']
    date_hierarchy = 'first_seen'


@admin.register(BlockedPhoneNumber)
class BlockedPhoneNumberAdmin(admin.ModelAdmin):
    list_display = ['phone_number', 'country_code', 'threat_type', 'source', 'report_count', 'is_active']
    list_filter = ['country_code', 'threat_type', 'is_active']
    search_fields = ['phone_number']
    date_hierarchy = 'first_seen'


@admin.register(ScamPattern)
class ScamPatternAdmin(admin.ModelAdmin):
    list_display = ['name', 'pattern_type', 'weight', 'is_active', 'false_positive_rate']
    list_filter = ['pattern_type', 'is_active', 'threat_types']
    search_fields = ['name', 'pattern', 'description']
    filter_horizontal = ['threat_types']


@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ['key', 'is_sensitive', 'updated_at']
    list_filter = ['is_sensitive']
    search_fields = ['key', 'description']
