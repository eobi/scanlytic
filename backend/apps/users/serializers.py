"""
Serializers for User management.
"""

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate

from .models import User, APIKey, UserActivity, Subscription


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""

    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'company', 'country'
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match'
            })
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(username=email, password=password)

        if not user:
            raise serializers.ValidationError('Invalid email or password')

        if not user.is_active:
            raise serializers.ValidationError('User account is disabled')

        attrs['user'] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user profile."""

    remaining_requests = serializers.ReadOnlyField()
    daily_limit = serializers.ReadOnlyField()
    is_plan_active = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name',
            'company', 'phone', 'country', 'timezone',
            'plan', 'plan_started_at', 'plan_expires_at',
            'daily_request_count', 'monthly_request_count', 'total_request_count',
            'remaining_requests', 'daily_limit', 'is_plan_active',
            'email_notifications', 'webhook_enabled', 'webhook_url',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'email', 'plan', 'plan_started_at', 'plan_expires_at',
            'daily_request_count', 'monthly_request_count', 'total_request_count',
            'created_at', 'updated_at'
        ]


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile."""

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'company', 'phone',
            'country', 'timezone', 'email_notifications',
            'webhook_enabled', 'webhook_url'
        ]


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""

    current_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Current password is incorrect')
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match'
            })
        return attrs


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for API keys."""

    key = serializers.CharField(read_only=True)

    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key', 'scopes',
            'allowed_ips', 'allowed_domains',
            'is_active', 'expires_at',
            'last_used_at', 'request_count',
            'created_at'
        ]
        read_only_fields = [
            'id', 'key', 'last_used_at', 'request_count', 'created_at'
        ]


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating API keys."""

    class Meta:
        model = APIKey
        fields = ['name', 'scopes', 'allowed_ips', 'allowed_domains', 'expires_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class UserActivitySerializer(serializers.ModelSerializer):
    """Serializer for user activity logs."""

    class Meta:
        model = UserActivity
        fields = ['id', 'action', 'ip_address', 'metadata', 'created_at']
        read_only_fields = ['id', 'action', 'ip_address', 'metadata', 'created_at']


class SubscriptionSerializer(serializers.ModelSerializer):
    """Serializer for subscriptions."""

    class Meta:
        model = Subscription
        fields = [
            'id', 'plan', 'status', 'billing_cycle',
            'started_at', 'expires_at', 'price_cents', 'currency',
            'created_at'
        ]
        read_only_fields = '__all__'


class UsageStatsSerializer(serializers.Serializer):
    """Serializer for usage statistics."""

    plan = serializers.CharField()
    daily_limit = serializers.IntegerField()
    daily_used = serializers.IntegerField()
    daily_remaining = serializers.IntegerField()
    monthly_used = serializers.IntegerField()
    total_used = serializers.IntegerField()
    plan_expires_at = serializers.DateTimeField(allow_null=True)
    is_plan_active = serializers.BooleanField()
