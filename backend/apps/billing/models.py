"""
Billing Models for Stripe Integration.

Handles subscription management, payment processing, usage tracking,
and invoice management for the Scamlytic platform.
"""

import uuid
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinValueValidator


class SubscriptionPlan(models.Model):
    """
    Subscription plan definitions synced with Stripe Products/Prices.
    """
    PLAN_TIERS = [
        ('free', 'Free'),
        ('basic', 'Basic'),
        ('pro', 'Pro'),
        ('enterprise', 'Enterprise'),
    ]

    BILLING_PERIODS = [
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    tier = models.CharField(max_length=20, choices=PLAN_TIERS, unique=True)
    description = models.TextField(blank=True)

    # Stripe IDs
    stripe_product_id = models.CharField(max_length=100, blank=True, db_index=True)
    stripe_price_id_monthly = models.CharField(max_length=100, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=100, blank=True)

    # Pricing
    price_monthly = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00')
    )
    price_yearly = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00')
    )
    currency = models.CharField(max_length=3, default='USD')

    # Limits
    daily_request_limit = models.IntegerField(default=100)
    monthly_request_limit = models.IntegerField(default=3000)
    api_keys_limit = models.IntegerField(default=1)
    webhook_limit = models.IntegerField(default=0)

    # Features
    features = models.JSONField(default=dict, blank=True)
    # Example: {"deep_scan": true, "llm_analysis": true, "priority_support": false}

    # Settings
    is_active = models.BooleanField(default=True)
    is_popular = models.BooleanField(default=False)  # For UI badge
    sort_order = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['sort_order', 'price_monthly']

    def __str__(self):
        return f"{self.name} (${self.price_monthly}/mo)"

    def get_stripe_price_id(self, billing_period='monthly'):
        """Get Stripe price ID for billing period."""
        if billing_period == 'yearly':
            return self.stripe_price_id_yearly
        return self.stripe_price_id_monthly


class Customer(models.Model):
    """
    Stripe Customer linked to User account.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='stripe_customer'
    )

    # Stripe IDs
    stripe_customer_id = models.CharField(max_length=100, unique=True, db_index=True)

    # Billing info
    email = models.EmailField()
    name = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=50, blank=True)

    # Address
    address_line1 = models.CharField(max_length=255, blank=True)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=2, blank=True)  # ISO country code

    # Tax info
    tax_id = models.CharField(max_length=100, blank=True)
    tax_exempt = models.BooleanField(default=False)

    # Payment method
    default_payment_method_id = models.CharField(max_length=100, blank=True)
    payment_method_type = models.CharField(max_length=50, blank=True)  # card, bank_transfer
    card_last4 = models.CharField(max_length=4, blank=True)
    card_brand = models.CharField(max_length=20, blank=True)  # visa, mastercard
    card_exp_month = models.IntegerField(null=True, blank=True)
    card_exp_year = models.IntegerField(null=True, blank=True)

    # Account status
    balance = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00')
    )
    currency = models.CharField(max_length=3, default='USD')
    delinquent = models.BooleanField(default=False)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['stripe_customer_id']),
            models.Index(fields=['email']),
        ]

    def __str__(self):
        return f"Customer: {self.email} ({self.stripe_customer_id})"


class Subscription(models.Model):
    """
    Stripe Subscription tracking.
    """
    STATUS_CHOICES = [
        ('incomplete', 'Incomplete'),
        ('incomplete_expired', 'Incomplete Expired'),
        ('trialing', 'Trialing'),
        ('active', 'Active'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('unpaid', 'Unpaid'),
        ('paused', 'Paused'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='subscriptions'
    )
    plan = models.ForeignKey(
        SubscriptionPlan,
        on_delete=models.PROTECT,
        related_name='subscriptions'
    )

    # Stripe IDs
    stripe_subscription_id = models.CharField(max_length=100, unique=True, db_index=True)
    stripe_price_id = models.CharField(max_length=100)

    # Status
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='incomplete')
    billing_period = models.CharField(max_length=10, default='monthly')

    # Dates
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    trial_start = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)
    canceled_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    # Billing
    cancel_at_period_end = models.BooleanField(default=False)
    collection_method = models.CharField(max_length=30, default='charge_automatically')

    # Usage-based billing
    quantity = models.IntegerField(default=1)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['stripe_subscription_id']),
            models.Index(fields=['status']),
            models.Index(fields=['current_period_end']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.customer.email} - {self.plan.name} ({self.status})"

    @property
    def is_active(self):
        """Check if subscription is in active state."""
        return self.status in ['active', 'trialing']

    @property
    def is_trialing(self):
        """Check if subscription is in trial."""
        return self.status == 'trialing'

    @property
    def days_until_renewal(self):
        """Days until next billing cycle."""
        if self.current_period_end:
            delta = self.current_period_end - timezone.now()
            return max(0, delta.days)
        return 0


class Invoice(models.Model):
    """
    Stripe Invoice tracking.
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('open', 'Open'),
        ('paid', 'Paid'),
        ('void', 'Void'),
        ('uncollectible', 'Uncollectible'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='invoices'
    )
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invoices'
    )

    # Stripe IDs
    stripe_invoice_id = models.CharField(max_length=100, unique=True, db_index=True)

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # Amounts (in cents, converted to dollars for display)
    amount_due = models.IntegerField(default=0)  # In cents
    amount_paid = models.IntegerField(default=0)
    amount_remaining = models.IntegerField(default=0)
    subtotal = models.IntegerField(default=0)
    tax = models.IntegerField(default=0)
    total = models.IntegerField(default=0)
    currency = models.CharField(max_length=3, default='usd')

    # Details
    description = models.TextField(blank=True)
    invoice_number = models.CharField(max_length=100, blank=True)
    invoice_pdf = models.URLField(blank=True)
    hosted_invoice_url = models.URLField(blank=True)

    # Dates
    period_start = models.DateTimeField(null=True, blank=True)
    period_end = models.DateTimeField(null=True, blank=True)
    due_date = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    # Line items stored as JSON
    lines = models.JSONField(default=list, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['stripe_invoice_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"Invoice {self.invoice_number} - ${self.total/100:.2f} ({self.status})"

    @property
    def amount_due_dollars(self):
        return Decimal(self.amount_due) / 100

    @property
    def total_dollars(self):
        return Decimal(self.total) / 100


class PaymentMethod(models.Model):
    """
    Stored payment methods for a customer.
    """
    TYPE_CHOICES = [
        ('card', 'Card'),
        ('bank_account', 'Bank Account'),
        ('sepa_debit', 'SEPA Debit'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='payment_methods'
    )

    # Stripe ID
    stripe_payment_method_id = models.CharField(max_length=100, unique=True, db_index=True)

    # Type
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='card')
    is_default = models.BooleanField(default=False)

    # Card details (if type=card)
    card_brand = models.CharField(max_length=20, blank=True)  # visa, mastercard, amex
    card_last4 = models.CharField(max_length=4, blank=True)
    card_exp_month = models.IntegerField(null=True, blank=True)
    card_exp_year = models.IntegerField(null=True, blank=True)
    card_funding = models.CharField(max_length=20, blank=True)  # credit, debit, prepaid

    # Bank account details (if type=bank_account)
    bank_name = models.CharField(max_length=100, blank=True)
    bank_last4 = models.CharField(max_length=4, blank=True)

    # Billing details
    billing_name = models.CharField(max_length=255, blank=True)
    billing_email = models.EmailField(blank=True)
    billing_phone = models.CharField(max_length=50, blank=True)
    billing_address = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['stripe_payment_method_id']),
        ]

    def __str__(self):
        if self.type == 'card':
            return f"{self.card_brand} ****{self.card_last4}"
        return f"{self.type} ****{self.bank_last4}"


class UsageRecord(models.Model):
    """
    Track API usage for metered billing.
    """
    USAGE_TYPES = [
        ('message_analysis', 'Message Analysis'),
        ('url_analysis', 'URL Analysis'),
        ('phone_analysis', 'Phone Analysis'),
        ('image_analysis', 'Image/Catfish Analysis'),
        ('batch_analysis', 'Batch Analysis'),
        ('api_call', 'Generic API Call'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='usage_records'
    )
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='usage_records'
    )

    # Usage details
    usage_type = models.CharField(max_length=30, choices=USAGE_TYPES)
    quantity = models.IntegerField(default=1, validators=[MinValueValidator(1)])

    # For Stripe metered billing
    stripe_usage_record_id = models.CharField(max_length=100, blank=True)
    reported_to_stripe = models.BooleanField(default=False)

    # Request details
    request_id = models.CharField(max_length=100, blank=True)
    endpoint = models.CharField(max_length=255, blank=True)

    # Timing
    timestamp = models.DateTimeField(default=timezone.now)
    billing_period_start = models.DateField()
    billing_period_end = models.DateField()

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['customer', 'timestamp']),
            models.Index(fields=['billing_period_start', 'billing_period_end']),
            models.Index(fields=['usage_type']),
        ]

    def __str__(self):
        return f"{self.customer.email} - {self.usage_type} x{self.quantity}"


class UsageSummary(models.Model):
    """
    Daily/Monthly usage summaries for quick lookups and billing.
    """
    PERIOD_TYPES = [
        ('daily', 'Daily'),
        ('monthly', 'Monthly'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='usage_summaries'
    )

    period_type = models.CharField(max_length=10, choices=PERIOD_TYPES)
    period_start = models.DateField()
    period_end = models.DateField()

    # Usage counts by type
    message_analyses = models.IntegerField(default=0)
    url_analyses = models.IntegerField(default=0)
    phone_analyses = models.IntegerField(default=0)
    image_analyses = models.IntegerField(default=0)
    batch_analyses = models.IntegerField(default=0)
    total_requests = models.IntegerField(default=0)

    # Limits
    daily_limit = models.IntegerField(default=0)
    monthly_limit = models.IntegerField(default=0)
    limit_reached = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['customer', 'period_type', 'period_start']
        indexes = [
            models.Index(fields=['customer', 'period_type', 'period_start']),
        ]

    def __str__(self):
        return f"{self.customer.email} - {self.period_type} ({self.period_start})"

    @property
    def usage_percentage(self):
        """Calculate usage percentage of limit."""
        limit = self.daily_limit if self.period_type == 'daily' else self.monthly_limit
        if limit > 0:
            return min(100, (self.total_requests / limit) * 100)
        return 0


class WebhookEvent(models.Model):
    """
    Log Stripe webhook events for debugging and idempotency.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Stripe event details
    stripe_event_id = models.CharField(max_length=100, unique=True, db_index=True)
    event_type = models.CharField(max_length=100, db_index=True)
    api_version = models.CharField(max_length=20, blank=True)

    # Processing status
    processed = models.BooleanField(default=False)
    processing_error = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)

    # Event data
    data = models.JSONField(default=dict)

    # Timestamps
    event_created_at = models.DateTimeField()
    processed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['stripe_event_id']),
            models.Index(fields=['event_type']),
            models.Index(fields=['processed']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.event_type} ({self.stripe_event_id})"


class Coupon(models.Model):
    """
    Stripe Coupon/Promotion codes.
    """
    DURATION_CHOICES = [
        ('once', 'Once'),
        ('repeating', 'Repeating'),
        ('forever', 'Forever'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Stripe IDs
    stripe_coupon_id = models.CharField(max_length=100, unique=True, db_index=True)
    stripe_promotion_code_id = models.CharField(max_length=100, blank=True)

    # Coupon details
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)

    # Discount
    percent_off = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    amount_off = models.IntegerField(null=True, blank=True)  # In cents
    currency = models.CharField(max_length=3, default='usd')

    # Duration
    duration = models.CharField(max_length=20, choices=DURATION_CHOICES)
    duration_in_months = models.IntegerField(null=True, blank=True)

    # Restrictions
    max_redemptions = models.IntegerField(null=True, blank=True)
    times_redeemed = models.IntegerField(default=0)
    valid = models.BooleanField(default=True)
    redeem_by = models.DateTimeField(null=True, blank=True)

    # Applicable plans
    applies_to_plans = models.ManyToManyField(
        SubscriptionPlan,
        blank=True,
        related_name='coupons'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['valid']),
        ]

    def __str__(self):
        if self.percent_off:
            return f"{self.code} - {self.percent_off}% off"
        return f"{self.code} - ${self.amount_off/100:.2f} off"

    @property
    def is_valid(self):
        """Check if coupon is currently valid."""
        if not self.valid:
            return False
        if self.redeem_by and timezone.now() > self.redeem_by:
            return False
        if self.max_redemptions and self.times_redeemed >= self.max_redemptions:
            return False
        return True
