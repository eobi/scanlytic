"""
Core Models for Scamlytic API.

Base models and shared functionality used across all apps.
"""

import uuid
from django.db import models
from django.utils import timezone


class TimeStampedModel(models.Model):
    """
    Abstract base model with created and updated timestamps.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ['-created_at']


class ThreatType(models.Model):
    """
    Threat type definitions for classification.
    """
    code = models.CharField(max_length=50, unique=True, primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        default='medium'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Threat Type'
        verbose_name_plural = 'Threat Types'
        ordering = ['name']

    def __str__(self):
        return f"{self.code}: {self.name}"


class SignalType(models.Model):
    """
    Signal/indicator types for detection.
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('moderate', 'Moderate'),
        ('low', 'Low'),
    ]

    code = models.CharField(max_length=50, unique=True, primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='moderate')
    weight = models.IntegerField(default=10, help_text="Score weight for this signal")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Signal Type'
        verbose_name_plural = 'Signal Types'
        ordering = ['severity', 'name']

    def __str__(self):
        return f"{self.code} ({self.severity})"


class BlockedDomain(models.Model):
    """
    Known malicious domains database.
    """
    domain = models.CharField(max_length=255, unique=True, db_index=True)
    threat_type = models.ForeignKey(
        ThreatType,
        on_delete=models.CASCADE,
        related_name='blocked_domains'
    )
    source = models.CharField(max_length=100, help_text="Source of this entry")
    confidence = models.FloatField(default=1.0, help_text="Confidence score 0-1")
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    report_count = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = 'Blocked Domain'
        verbose_name_plural = 'Blocked Domains'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['domain', 'is_active']),
            models.Index(fields=['threat_type', 'is_active']),
        ]

    def __str__(self):
        return self.domain


class BlockedPhoneNumber(models.Model):
    """
    Known scam phone numbers database.
    """
    phone_number = models.CharField(max_length=20, unique=True, db_index=True)
    country_code = models.CharField(max_length=5, blank=True)
    threat_type = models.ForeignKey(
        ThreatType,
        on_delete=models.CASCADE,
        related_name='blocked_phones'
    )
    source = models.CharField(max_length=100)
    confidence = models.FloatField(default=1.0)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    report_count = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = 'Blocked Phone Number'
        verbose_name_plural = 'Blocked Phone Numbers'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['phone_number', 'is_active']),
            models.Index(fields=['country_code', 'is_active']),
        ]

    def __str__(self):
        return self.phone_number


class ScamPattern(models.Model):
    """
    Regex patterns for detecting scam content.
    """
    PATTERN_TYPE_CHOICES = [
        ('regex', 'Regular Expression'),
        ('keyword', 'Keyword Match'),
        ('phrase', 'Phrase Match'),
        ('semantic', 'Semantic Pattern'),
    ]

    name = models.CharField(max_length=100)
    pattern = models.TextField(help_text="Regex pattern or keyword")
    pattern_type = models.CharField(max_length=20, choices=PATTERN_TYPE_CHOICES, default='regex')
    threat_types = models.ManyToManyField(ThreatType, related_name='patterns')
    weight = models.IntegerField(default=10, help_text="Score contribution when matched")
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    false_positive_rate = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Scam Pattern'
        verbose_name_plural = 'Scam Patterns'
        ordering = ['-weight']

    def __str__(self):
        return self.name


class SystemConfig(models.Model):
    """
    System configuration storage.
    """
    key = models.CharField(max_length=100, unique=True, primary_key=True)
    value = models.JSONField()
    description = models.TextField(blank=True)
    is_sensitive = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'System Configuration'
        verbose_name_plural = 'System Configurations'

    def __str__(self):
        return self.key
