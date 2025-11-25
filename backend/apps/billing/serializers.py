"""
Billing Serializers for API endpoints.
"""

from rest_framework import serializers
from decimal import Decimal

from .models import (
    SubscriptionPlan, Customer, Subscription, Invoice,
    PaymentMethod, UsageRecord, UsageSummary, Coupon
)


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """Serializer for subscription plans."""

    monthly_price_display = serializers.SerializerMethodField()
    yearly_price_display = serializers.SerializerMethodField()
    yearly_savings = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'tier', 'description',
            'price_monthly', 'price_yearly', 'currency',
            'monthly_price_display', 'yearly_price_display', 'yearly_savings',
            'daily_request_limit', 'monthly_request_limit',
            'api_keys_limit', 'webhook_limit',
            'features', 'is_active', 'is_popular',
        ]

    def get_monthly_price_display(self, obj):
        if obj.price_monthly == 0:
            return 'Free'
        return f'${obj.price_monthly:.2f}/mo'

    def get_yearly_price_display(self, obj):
        if obj.price_yearly == 0:
            return 'Free'
        monthly_equiv = obj.price_yearly / 12
        return f'${monthly_equiv:.2f}/mo'

    def get_yearly_savings(self, obj):
        if obj.price_monthly == 0:
            return 0
        yearly_from_monthly = obj.price_monthly * 12
        savings = yearly_from_monthly - obj.price_yearly
        return float(savings)


class PaymentMethodSerializer(serializers.ModelSerializer):
    """Serializer for payment methods."""

    display_name = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'type', 'is_default',
            'card_brand', 'card_last4', 'card_exp_month', 'card_exp_year',
            'card_funding', 'bank_name', 'bank_last4',
            'billing_name', 'billing_email',
            'display_name', 'is_expired',
            'created_at',
        ]

    def get_display_name(self, obj):
        if obj.type == 'card':
            return f'{obj.card_brand.title()} ending in {obj.card_last4}'
        elif obj.type == 'bank_account':
            return f'{obj.bank_name} ending in {obj.bank_last4}'
        return obj.type

    def get_is_expired(self, obj):
        if obj.type != 'card' or not obj.card_exp_month or not obj.card_exp_year:
            return False
        from datetime import datetime
        now = datetime.now()
        return (obj.card_exp_year < now.year or
                (obj.card_exp_year == now.year and obj.card_exp_month < now.month))


class CustomerSerializer(serializers.ModelSerializer):
    """Serializer for customer details."""

    payment_methods = PaymentMethodSerializer(many=True, read_only=True)
    has_active_subscription = serializers.SerializerMethodField()
    current_plan = serializers.SerializerMethodField()

    class Meta:
        model = Customer
        fields = [
            'id', 'email', 'name', 'phone',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country',
            'default_payment_method_id', 'card_last4', 'card_brand',
            'balance', 'currency', 'delinquent',
            'payment_methods', 'has_active_subscription', 'current_plan',
            'created_at',
        ]

    def get_has_active_subscription(self, obj):
        return obj.subscriptions.filter(status__in=['active', 'trialing']).exists()

    def get_current_plan(self, obj):
        sub = obj.subscriptions.filter(status__in=['active', 'trialing']).first()
        if sub:
            return {
                'name': sub.plan.name,
                'tier': sub.plan.tier,
                'status': sub.status,
            }
        return {'name': 'Free', 'tier': 'free', 'status': 'active'}


class CustomerUpdateSerializer(serializers.Serializer):
    """Serializer for updating customer details."""

    email = serializers.EmailField(required=False)
    name = serializers.CharField(max_length=255, required=False)
    phone = serializers.CharField(max_length=50, required=False, allow_blank=True)
    address_line1 = serializers.CharField(max_length=255, required=False, allow_blank=True)
    address_line2 = serializers.CharField(max_length=255, required=False, allow_blank=True)
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    state = serializers.CharField(max_length=100, required=False, allow_blank=True)
    postal_code = serializers.CharField(max_length=20, required=False, allow_blank=True)
    country = serializers.CharField(max_length=2, required=False, allow_blank=True)


class SubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for subscriptions."""

    plan = SubscriptionPlanSerializer(read_only=True)
    days_until_renewal = serializers.ReadOnlyField()
    is_active = serializers.ReadOnlyField()
    is_trialing = serializers.ReadOnlyField()

    class Meta:
        model = Subscription
        fields = [
            'id', 'plan', 'status', 'billing_period',
            'current_period_start', 'current_period_end',
            'trial_start', 'trial_end',
            'cancel_at_period_end', 'canceled_at', 'ended_at',
            'days_until_renewal', 'is_active', 'is_trialing',
            'created_at',
        ]


class CreateSubscriptionSerializer(serializers.Serializer):
    """Serializer for creating subscriptions."""

    plan_id = serializers.UUIDField()
    billing_period = serializers.ChoiceField(
        choices=['monthly', 'yearly'],
        default='monthly'
    )
    payment_method_id = serializers.CharField(required=False, allow_blank=True)
    coupon_code = serializers.CharField(required=False, allow_blank=True)

    def validate_plan_id(self, value):
        try:
            plan = SubscriptionPlan.objects.get(id=value, is_active=True)
            return plan
        except SubscriptionPlan.DoesNotExist:
            raise serializers.ValidationError('Invalid or inactive plan')


class UpdateSubscriptionSerializer(serializers.Serializer):
    """Serializer for updating subscriptions."""

    plan_id = serializers.UUIDField(required=False)
    billing_period = serializers.ChoiceField(
        choices=['monthly', 'yearly'],
        required=False
    )

    def validate_plan_id(self, value):
        if value:
            try:
                plan = SubscriptionPlan.objects.get(id=value, is_active=True)
                return plan
            except SubscriptionPlan.DoesNotExist:
                raise serializers.ValidationError('Invalid or inactive plan')
        return value


class CancelSubscriptionSerializer(serializers.Serializer):
    """Serializer for canceling subscriptions."""

    immediately = serializers.BooleanField(default=False)
    reason = serializers.CharField(required=False, allow_blank=True)


class InvoiceSerializer(serializers.ModelSerializer):
    """Serializer for invoices."""

    amount_due_dollars = serializers.ReadOnlyField()
    total_dollars = serializers.ReadOnlyField()

    class Meta:
        model = Invoice
        fields = [
            'id', 'status', 'invoice_number',
            'amount_due', 'amount_paid', 'amount_remaining',
            'subtotal', 'tax', 'total', 'currency',
            'amount_due_dollars', 'total_dollars',
            'description', 'invoice_pdf', 'hosted_invoice_url',
            'period_start', 'period_end', 'due_date', 'paid_at',
            'lines', 'created_at',
        ]


class UsageRecordSerializer(serializers.ModelSerializer):
    """Serializer for usage records."""

    class Meta:
        model = UsageRecord
        fields = [
            'id', 'usage_type', 'quantity',
            'endpoint', 'request_id',
            'timestamp', 'billing_period_start', 'billing_period_end',
        ]


class UsageSummarySerializer(serializers.ModelSerializer):
    """Serializer for usage summaries."""

    usage_percentage = serializers.ReadOnlyField()

    class Meta:
        model = UsageSummary
        fields = [
            'id', 'period_type', 'period_start', 'period_end',
            'message_analyses', 'url_analyses', 'phone_analyses',
            'image_analyses', 'batch_analyses', 'total_requests',
            'daily_limit', 'monthly_limit', 'limit_reached',
            'usage_percentage',
        ]


class UsageLimitsSerializer(serializers.Serializer):
    """Serializer for usage limit check response."""

    allowed = serializers.BooleanField()
    daily = serializers.DictField()
    monthly = serializers.DictField()
    upgrade_required = serializers.BooleanField()


class UsageStatsSerializer(serializers.Serializer):
    """Serializer for usage statistics response."""

    period = serializers.DictField()
    daily = serializers.ListField()
    totals = serializers.DictField()
    current_limits = UsageLimitsSerializer()


class CouponSerializer(serializers.ModelSerializer):
    """Serializer for coupons."""

    is_valid = serializers.ReadOnlyField()
    discount_display = serializers.SerializerMethodField()

    class Meta:
        model = Coupon
        fields = [
            'id', 'code', 'name',
            'percent_off', 'amount_off', 'currency',
            'duration', 'duration_in_months',
            'is_valid', 'discount_display',
            'redeem_by',
        ]

    def get_discount_display(self, obj):
        if obj.percent_off:
            return f'{obj.percent_off}% off'
        elif obj.amount_off:
            return f'${obj.amount_off / 100:.2f} off'
        return ''


class ValidateCouponSerializer(serializers.Serializer):
    """Serializer for coupon validation."""

    code = serializers.CharField()
    plan_id = serializers.UUIDField(required=False)


class CheckoutSessionSerializer(serializers.Serializer):
    """Serializer for creating checkout sessions."""

    plan_id = serializers.UUIDField()
    billing_period = serializers.ChoiceField(
        choices=['monthly', 'yearly'],
        default='monthly'
    )
    success_url = serializers.URLField(required=False)
    cancel_url = serializers.URLField(required=False)
    coupon_code = serializers.CharField(required=False, allow_blank=True)

    def validate_plan_id(self, value):
        try:
            plan = SubscriptionPlan.objects.get(id=value, is_active=True)
            return plan
        except SubscriptionPlan.DoesNotExist:
            raise serializers.ValidationError('Invalid or inactive plan')


class BillingPortalSerializer(serializers.Serializer):
    """Serializer for billing portal session."""

    return_url = serializers.URLField(required=False)


class SetupIntentSerializer(serializers.Serializer):
    """Response serializer for setup intent."""

    client_secret = serializers.CharField()
    setup_intent_id = serializers.CharField()


class AttachPaymentMethodSerializer(serializers.Serializer):
    """Serializer for attaching payment methods."""

    payment_method_id = serializers.CharField()
    set_as_default = serializers.BooleanField(default=True)
