"""
Billing Admin Configuration.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    SubscriptionPlan, Customer, Subscription, Invoice,
    PaymentMethod, UsageRecord, UsageSummary, WebhookEvent, Coupon
)


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'tier', 'price_monthly', 'price_yearly',
        'daily_request_limit', 'monthly_request_limit',
        'is_active', 'is_popular'
    ]
    list_filter = ['tier', 'is_active', 'is_popular']
    search_fields = ['name', 'tier']
    ordering = ['sort_order', 'price_monthly']

    fieldsets = (
        (None, {
            'fields': ('name', 'tier', 'description')
        }),
        ('Stripe Configuration', {
            'fields': (
                'stripe_product_id',
                'stripe_price_id_monthly',
                'stripe_price_id_yearly'
            )
        }),
        ('Pricing', {
            'fields': ('price_monthly', 'price_yearly', 'currency')
        }),
        ('Limits', {
            'fields': (
                'daily_request_limit', 'monthly_request_limit',
                'api_keys_limit', 'webhook_limit'
            )
        }),
        ('Features', {
            'fields': ('features',)
        }),
        ('Settings', {
            'fields': ('is_active', 'is_popular', 'sort_order')
        }),
    )


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = [
        'email', 'name', 'stripe_customer_id',
        'card_display', 'balance', 'delinquent', 'created_at'
    ]
    list_filter = ['delinquent', 'created_at']
    search_fields = ['email', 'name', 'stripe_customer_id', 'user__email']
    raw_id_fields = ['user']
    readonly_fields = ['stripe_customer_id', 'created_at', 'updated_at']

    def card_display(self, obj):
        if obj.card_last4:
            return f'{obj.card_brand} ****{obj.card_last4}'
        return '-'
    card_display.short_description = 'Card'


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = [
        'customer', 'plan', 'status', 'billing_period',
        'current_period_end', 'cancel_at_period_end', 'created_at'
    ]
    list_filter = ['status', 'billing_period', 'cancel_at_period_end', 'plan']
    search_fields = ['customer__email', 'stripe_subscription_id']
    raw_id_fields = ['customer', 'plan']
    readonly_fields = [
        'stripe_subscription_id', 'stripe_price_id',
        'created_at', 'updated_at'
    ]

    fieldsets = (
        (None, {
            'fields': ('customer', 'plan', 'status')
        }),
        ('Stripe', {
            'fields': ('stripe_subscription_id', 'stripe_price_id')
        }),
        ('Billing', {
            'fields': ('billing_period', 'quantity', 'collection_method')
        }),
        ('Dates', {
            'fields': (
                'current_period_start', 'current_period_end',
                'trial_start', 'trial_end',
                'canceled_at', 'ended_at'
            )
        }),
        ('Settings', {
            'fields': ('cancel_at_period_end', 'metadata')
        }),
    )


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = [
        'invoice_number', 'customer', 'status',
        'total_display', 'period_start', 'period_end', 'created_at'
    ]
    list_filter = ['status', 'created_at']
    search_fields = ['invoice_number', 'customer__email', 'stripe_invoice_id']
    raw_id_fields = ['customer', 'subscription']
    readonly_fields = [
        'stripe_invoice_id', 'invoice_pdf_link', 'hosted_invoice_link',
        'created_at', 'updated_at'
    ]

    def total_display(self, obj):
        return f'${obj.total / 100:.2f}'
    total_display.short_description = 'Total'

    def invoice_pdf_link(self, obj):
        if obj.invoice_pdf:
            return format_html('<a href="{}" target="_blank">Download PDF</a>', obj.invoice_pdf)
        return '-'
    invoice_pdf_link.short_description = 'PDF'

    def hosted_invoice_link(self, obj):
        if obj.hosted_invoice_url:
            return format_html('<a href="{}" target="_blank">View Invoice</a>', obj.hosted_invoice_url)
        return '-'
    hosted_invoice_link.short_description = 'Hosted Invoice'


@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = [
        'customer', 'type', 'card_display', 'is_default', 'created_at'
    ]
    list_filter = ['type', 'is_default', 'card_brand']
    search_fields = ['customer__email', 'stripe_payment_method_id']
    raw_id_fields = ['customer']

    def card_display(self, obj):
        if obj.type == 'card':
            return f'{obj.card_brand} ****{obj.card_last4}'
        return f'{obj.type}'
    card_display.short_description = 'Payment Method'


@admin.register(UsageRecord)
class UsageRecordAdmin(admin.ModelAdmin):
    list_display = [
        'customer', 'usage_type', 'quantity',
        'endpoint', 'timestamp', 'billing_period_start'
    ]
    list_filter = ['usage_type', 'timestamp']
    search_fields = ['customer__email', 'endpoint', 'request_id']
    raw_id_fields = ['customer', 'subscription']
    date_hierarchy = 'timestamp'
    readonly_fields = ['created_at']


@admin.register(UsageSummary)
class UsageSummaryAdmin(admin.ModelAdmin):
    list_display = [
        'customer', 'period_type', 'period_start',
        'total_requests', 'usage_percent', 'limit_reached'
    ]
    list_filter = ['period_type', 'limit_reached', 'period_start']
    search_fields = ['customer__email']
    raw_id_fields = ['customer']
    date_hierarchy = 'period_start'

    def usage_percent(self, obj):
        return f'{obj.usage_percentage:.1f}%'
    usage_percent.short_description = 'Usage %'


@admin.register(WebhookEvent)
class WebhookEventAdmin(admin.ModelAdmin):
    list_display = [
        'stripe_event_id', 'event_type', 'processed',
        'processing_error_short', 'event_created_at', 'processed_at'
    ]
    list_filter = ['event_type', 'processed', 'event_created_at']
    search_fields = ['stripe_event_id', 'event_type']
    readonly_fields = [
        'stripe_event_id', 'event_type', 'api_version',
        'data', 'event_created_at', 'created_at'
    ]
    date_hierarchy = 'event_created_at'

    def processing_error_short(self, obj):
        if obj.processing_error:
            return obj.processing_error[:50] + '...' if len(obj.processing_error) > 50 else obj.processing_error
        return '-'
    processing_error_short.short_description = 'Error'


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = [
        'code', 'name', 'discount_display', 'duration',
        'times_redeemed', 'valid', 'redeem_by'
    ]
    list_filter = ['valid', 'duration']
    search_fields = ['code', 'name', 'stripe_coupon_id']
    filter_horizontal = ['applies_to_plans']

    def discount_display(self, obj):
        if obj.percent_off:
            return f'{obj.percent_off}% off'
        elif obj.amount_off:
            return f'${obj.amount_off / 100:.2f} off'
        return '-'
    discount_display.short_description = 'Discount'
