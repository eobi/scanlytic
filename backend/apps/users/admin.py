"""
Admin configuration for User models.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User, APIKey, UserActivity, Subscription


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'first_name', 'last_name', 'plan', 'is_active', 'created_at']
    list_filter = ['plan', 'is_active', 'is_staff', 'created_at']
    search_fields = ['email', 'first_name', 'last_name', 'company']
    ordering = ['-created_at']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'company', 'phone', 'country')}),
        ('Plan & Usage', {
            'fields': (
                'plan', 'plan_started_at', 'plan_expires_at',
                'daily_request_count', 'monthly_request_count', 'total_request_count'
            )
        }),
        ('Preferences', {'fields': ('email_notifications', 'webhook_enabled', 'webhook_url', 'timezone')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )

    readonly_fields = ['created_at', 'updated_at', 'last_login']

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'plan'),
        }),
    )


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'is_active', 'request_count', 'last_used_at', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'user__email', 'key']
    raw_id_fields = ['user']
    readonly_fields = ['key', 'key_hash', 'request_count', 'last_used_at', 'created_at']


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'ip_address', 'created_at']
    list_filter = ['action', 'created_at']
    search_fields = ['user__email', 'ip_address']
    raw_id_fields = ['user']
    readonly_fields = ['created_at']


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ['user', 'plan', 'status', 'billing_cycle', 'started_at', 'expires_at']
    list_filter = ['plan', 'status', 'billing_cycle']
    search_fields = ['user__email', 'stripe_subscription_id']
    raw_id_fields = ['user']
    readonly_fields = ['created_at']
