"""
User models for Scamlytic API.

Includes custom User model, API keys, and subscription management.
"""

import uuid
import secrets
import hashlib
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
from django.conf import settings

from apps.core.models import TimeStampedModel


class UserManager(BaseUserManager):
    """Custom user manager."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('plan', 'enterprise')
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom User model for Scamlytic.
    """
    PLAN_CHOICES = [
        ('free', 'Free'),
        ('pro', 'Pro'),
        ('developer', 'Developer'),
        ('business', 'Business'),
        ('enterprise', 'Enterprise'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # Remove username, use email
    email = models.EmailField(unique=True, db_index=True)

    # Profile information
    company = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True)
    timezone = models.CharField(max_length=50, default='UTC')

    # Plan & Subscription
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='free')
    plan_started_at = models.DateTimeField(null=True, blank=True)
    plan_expires_at = models.DateTimeField(null=True, blank=True)

    # Usage tracking
    daily_request_count = models.IntegerField(default=0)
    monthly_request_count = models.IntegerField(default=0)
    total_request_count = models.IntegerField(default=0)
    last_request_at = models.DateTimeField(null=True, blank=True)
    last_request_reset = models.DateField(null=True, blank=True)

    # Preferences
    email_notifications = models.BooleanField(default=True)
    webhook_enabled = models.BooleanField(default=False)
    webhook_url = models.URLField(blank=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['plan']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.email

    @property
    def daily_limit(self):
        """Get daily request limit for user's plan."""
        return settings.PLAN_RATE_LIMITS.get(self.plan, 50)

    @property
    def remaining_requests(self):
        """Get remaining requests for today."""
        self._reset_daily_count_if_needed()
        return max(0, self.daily_limit - self.daily_request_count)

    def _reset_daily_count_if_needed(self):
        """Reset daily count if it's a new day."""
        today = timezone.now().date()
        if self.last_request_reset != today:
            self.daily_request_count = 0
            self.last_request_reset = today
            self.save(update_fields=['daily_request_count', 'last_request_reset'])

    def increment_request_count(self):
        """Increment request counters."""
        self._reset_daily_count_if_needed()
        self.daily_request_count += 1
        self.monthly_request_count += 1
        self.total_request_count += 1
        self.last_request_at = timezone.now()
        self.save(update_fields=[
            'daily_request_count', 'monthly_request_count',
            'total_request_count', 'last_request_at'
        ])

    def can_make_request(self):
        """Check if user can make another request."""
        self._reset_daily_count_if_needed()
        return self.daily_request_count < self.daily_limit

    @property
    def is_plan_active(self):
        """Check if current plan is active."""
        if self.plan == 'free':
            return True
        if self.plan_expires_at:
            return self.plan_expires_at > timezone.now()
        return True


class APIKey(TimeStampedModel):
    """
    API Key model for authentication.
    """
    PREFIX = 'scam_'
    KEY_LENGTH = 32

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='api_keys'
    )
    name = models.CharField(max_length=100, help_text="Friendly name for the key")
    key = models.CharField(max_length=100, unique=True, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)

    # Permissions
    scopes = models.JSONField(
        default=list,
        help_text="List of allowed scopes",
        blank=True
    )

    # Usage
    last_used_at = models.DateTimeField(null=True, blank=True)
    request_count = models.IntegerField(default=0)

    # Restrictions
    allowed_ips = models.JSONField(
        default=list,
        help_text="List of allowed IP addresses (empty = all)",
        blank=True
    )
    allowed_domains = models.JSONField(
        default=list,
        help_text="List of allowed referrer domains",
        blank=True
    )

    # Status
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['key', 'is_active']),
            models.Index(fields=['user', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key[:12]}...)"

    @classmethod
    def generate_key(cls):
        """Generate a new API key."""
        random_part = secrets.token_hex(cls.KEY_LENGTH // 2)
        return f"{cls.PREFIX}{random_part}"

    @classmethod
    def hash_key(cls, key):
        """Create a hash of the key for secure storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        if not self.key_hash:
            self.key_hash = self.hash_key(self.key)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if the key is valid and active."""
        if not self.is_active:
            return False
        if self.revoked_at:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def record_usage(self, ip_address=None):
        """Record API key usage."""
        self.last_used_at = timezone.now()
        self.request_count += 1
        self.save(update_fields=['last_used_at', 'request_count'])

    def revoke(self):
        """Revoke the API key."""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=['is_active', 'revoked_at'])


class UserActivity(TimeStampedModel):
    """
    Track user activity and actions.
    """
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('api_call', 'API Call'),
        ('key_created', 'API Key Created'),
        ('key_revoked', 'API Key Revoked'),
        ('plan_changed', 'Plan Changed'),
        ('password_changed', 'Password Changed'),
        ('profile_updated', 'Profile Updated'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='activities'
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'action']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.user.email}: {self.action}"


class Subscription(TimeStampedModel):
    """
    Subscription and billing management.
    """
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
        ('trial', 'Trial'),
        ('past_due', 'Past Due'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='subscriptions'
    )
    plan = models.CharField(max_length=20, choices=User.PLAN_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')

    # Billing
    stripe_subscription_id = models.CharField(max_length=100, blank=True)
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    billing_cycle = models.CharField(
        max_length=20,
        choices=[('monthly', 'Monthly'), ('annual', 'Annual')],
        default='monthly'
    )

    # Dates
    started_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)

    # Pricing
    price_cents = models.IntegerField(default=0)
    currency = models.CharField(max_length=3, default='USD')

    class Meta:
        verbose_name = 'Subscription'
        verbose_name_plural = 'Subscriptions'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.email}: {self.plan} ({self.status})"
