"""
Billing Middleware.

Provides usage metering and rate limiting based on subscription plans.
"""

import logging
import uuid
from django.http import JsonResponse
from django.utils import timezone

from .models import Customer
from .stripe_service import stripe_service

logger = logging.getLogger('scamlytic.billing.middleware')


class UsageMeteringMiddleware:
    """
    Middleware to track API usage and enforce rate limits.

    Tracks usage for authenticated users and enforces limits
    based on their subscription plan.
    """

    # Endpoints that count toward usage
    METERED_ENDPOINTS = {
        '/api/v1/analyze/message': 'message_analysis',
        '/api/v1/analyze/url': 'url_analysis',
        '/api/v1/analyze/phone': 'phone_analysis',
        '/api/v1/analyze/image': 'image_analysis',
        '/api/v1/analyze/batch': 'batch_analysis',
        '/api/v1/scan/': 'message_analysis',  # General scan endpoint
    }

    # Endpoints exempt from metering
    EXEMPT_ENDPOINTS = [
        '/api/v1/billing/',
        '/api/v1/auth/',
        '/api/v1/health/',
        '/admin/',
        '/api/schema/',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for exempt endpoints
        if self._is_exempt(request.path):
            return self.get_response(request)

        # Skip for non-authenticated users (they'll get 401 from views)
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return self.get_response(request)

        # Check if this is a metered endpoint
        usage_type = self._get_usage_type(request.path)
        if not usage_type:
            return self.get_response(request)

        # Check usage limits
        try:
            customer = self._get_customer(request.user)
            if customer:
                limits = stripe_service.check_usage_limit(customer)

                if not limits['allowed']:
                    return self._rate_limit_response(limits)

                # Generate request ID for tracking
                request.usage_request_id = str(uuid.uuid4())
                request.usage_type = usage_type
                request.billing_customer = customer

        except Exception as e:
            logger.error(f"Error checking usage limits: {e}")
            # Don't block on middleware errors
            pass

        # Process request
        response = self.get_response(request)

        # Record usage for successful requests
        if response.status_code in [200, 201] and hasattr(request, 'billing_customer'):
            self._record_usage(request, response)

        return response

    def _is_exempt(self, path):
        """Check if path is exempt from metering."""
        return any(path.startswith(exempt) for exempt in self.EXEMPT_ENDPOINTS)

    def _get_usage_type(self, path):
        """Get usage type for a path."""
        for endpoint, usage_type in self.METERED_ENDPOINTS.items():
            if path.startswith(endpoint):
                return usage_type
        return None

    def _get_customer(self, user):
        """Get or create customer for user."""
        try:
            return Customer.objects.get(user=user)
        except Customer.DoesNotExist:
            # Auto-create customer on first API call
            return stripe_service.get_or_create_customer(user)

    def _rate_limit_response(self, limits):
        """Return rate limit exceeded response."""
        daily = limits.get('daily', {})
        monthly = limits.get('monthly', {})

        if daily.get('exceeded'):
            message = f"Daily limit reached ({daily['limit']} requests). Resets at midnight UTC."
        else:
            message = f"Monthly limit reached ({monthly['limit']} requests). Upgrade your plan for more."

        return JsonResponse({
            'error': 'rate_limit_exceeded',
            'message': message,
            'limits': {
                'daily': {
                    'used': daily.get('used', 0),
                    'limit': daily.get('limit', 0),
                    'remaining': daily.get('remaining', 0),
                },
                'monthly': {
                    'used': monthly.get('used', 0),
                    'limit': monthly.get('limit', 0),
                    'remaining': monthly.get('remaining', 0),
                }
            },
            'upgrade_url': '/pricing',
        }, status=429)

    def _record_usage(self, request, response):
        """Record API usage after successful request."""
        try:
            stripe_service.record_usage(
                customer=request.billing_customer,
                usage_type=request.usage_type,
                quantity=1,
                request_id=getattr(request, 'usage_request_id', ''),
                endpoint=request.path,
                metadata={
                    'method': request.method,
                    'response_status': response.status_code,
                }
            )
        except Exception as e:
            logger.error(f"Error recording usage: {e}")


class SubscriptionRequiredMiddleware:
    """
    Middleware to enforce subscription requirements for premium endpoints.
    """

    # Endpoints requiring paid subscription
    PREMIUM_ENDPOINTS = {
        '/api/v1/analyze/batch': ['basic', 'pro', 'enterprise'],
        '/api/v1/reports/': ['pro', 'enterprise'],
        '/api/v1/webhooks/': ['pro', 'enterprise'],
        '/api/v1/export/': ['basic', 'pro', 'enterprise'],
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for non-authenticated users
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return self.get_response(request)

        # Check if premium endpoint
        required_tiers = self._get_required_tiers(request.path)
        if not required_tiers:
            return self.get_response(request)

        # Check user's plan
        user_plan = getattr(request.user, 'plan', 'free')
        if user_plan not in required_tiers:
            return self._upgrade_required_response(required_tiers)

        return self.get_response(request)

    def _get_required_tiers(self, path):
        """Get required subscription tiers for a path."""
        for endpoint, tiers in self.PREMIUM_ENDPOINTS.items():
            if path.startswith(endpoint):
                return tiers
        return None

    def _upgrade_required_response(self, required_tiers):
        """Return upgrade required response."""
        min_tier = required_tiers[0] if required_tiers else 'basic'

        return JsonResponse({
            'error': 'subscription_required',
            'message': f'This feature requires a {min_tier.title()} plan or higher.',
            'required_plans': required_tiers,
            'upgrade_url': '/pricing',
        }, status=403)


class UsageHeadersMiddleware:
    """
    Middleware to add usage information to response headers.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add usage headers for authenticated users
        if hasattr(request, 'user') and request.user.is_authenticated:
            try:
                customer = Customer.objects.get(user=request.user)
                limits = stripe_service.check_usage_limit(customer)

                daily = limits.get('daily', {})
                monthly = limits.get('monthly', {})

                response['X-RateLimit-Limit-Daily'] = str(daily.get('limit', 0))
                response['X-RateLimit-Remaining-Daily'] = str(daily.get('remaining', 0))
                response['X-RateLimit-Limit-Monthly'] = str(monthly.get('limit', 0))
                response['X-RateLimit-Remaining-Monthly'] = str(monthly.get('remaining', 0))

            except Customer.DoesNotExist:
                pass
            except Exception as e:
                logger.debug(f"Error adding usage headers: {e}")

        return response
