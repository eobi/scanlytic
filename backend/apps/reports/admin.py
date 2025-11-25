"""
Admin configuration for Reports models.
"""

from django.contrib import admin
from .models import Report, ReportTemplate, ScheduledReport


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['name', 'report_type', 'format', 'status', 'user', 'created_at']
    list_filter = ['report_type', 'format', 'status', 'created_at']
    search_fields = ['name', 'user__email']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'report_type', 'is_default', 'is_active']
    list_filter = ['report_type', 'is_default', 'is_active']
    search_fields = ['name']


@admin.register(ScheduledReport)
class ScheduledReportAdmin(admin.ModelAdmin):
    list_display = ['name', 'report_type', 'frequency', 'is_active', 'next_run_at', 'user']
    list_filter = ['frequency', 'is_active', 'report_type']
    search_fields = ['name', 'user__email']
    readonly_fields = ['last_run_at', 'created_at']
