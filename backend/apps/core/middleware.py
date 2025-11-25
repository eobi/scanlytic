"""
Custom middleware for Scamlytic API.
"""

import time
import logging
import uuid
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse

logger = logging.getLogger('scamlytic')


class RequestLoggingMiddleware:
    """
    Middleware for logging all API requests.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Generate unique request ID
        request_id = str(uuid.uuid4())[:8]
        request.request_id = request_id

        # Record start time
        start_time = time.time()

        # Get response
        response = self.get_response(request)

        # Calculate duration
        duration = time.time() - start_time

        # Log the request
        if not request.path.startswith('/admin/') and not request.path.startswith('/static/'):
            logger.info(
                f"API Request",
                extra={
                    'request_id': request_id,
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100],
                    'ip': self._get_client_ip(request),
                }
            )

        # Add request ID to response headers
        response['X-Request-ID'] = request_id
        response['X-Response-Time'] = f"{round(duration * 1000, 2)}ms"

        return response

    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class RateLimitMiddleware:
    """
    Middleware for API rate limiting.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip rate limiting for admin and health checks
        if request.path.startswith('/admin/') or request.path == '/health/':
            return self.get_response(request)

        # Get rate limit info
        rate_limit_info = self._check_rate_limit(request)

        if rate_limit_info['exceeded']:
            return JsonResponse(
                {
                    'error': {
                        'code': 'rate_limit_exceeded',
                        'message': 'Rate limit exceeded. Please try again later.',
                        'details': {
                            'limit': rate_limit_info['limit'],
                            'remaining': 0,
                            'reset': rate_limit_info['reset'],
                        }
                    }
                },
                status=429,
                headers={
                    'X-RateLimit-Limit': str(rate_limit_info['limit']),
                    'X-RateLimit-Remaining': '0',
                    'X-RateLimit-Reset': str(rate_limit_info['reset']),
                    'Retry-After': str(rate_limit_info['reset']),
                }
            )

        # Get response
        response = self.get_response(request)

        # Add rate limit headers
        response['X-RateLimit-Limit'] = str(rate_limit_info['limit'])
        response['X-RateLimit-Remaining'] = str(rate_limit_info['remaining'])
        response['X-RateLimit-Reset'] = str(rate_limit_info['reset'])

        return response

    def _check_rate_limit(self, request):
        """Check and update rate limit for the request."""
        # Determine rate limit based on authentication
        api_key = self._get_api_key(request)

        if api_key:
            # Get user's plan rate limit
            from apps.users.models import APIKey
            try:
                key_obj = APIKey.objects.select_related('user').get(
                    key=api_key, is_active=True
                )
                plan = key_obj.user.plan
                limit_per_minute = settings.PLAN_RATE_LIMITS_PER_MINUTE.get(plan, 10)
                cache_key = f"rate_limit:{api_key}"
            except APIKey.DoesNotExist:
                limit_per_minute = 10
                cache_key = f"rate_limit:anon:{self._get_client_ip(request)}"
        else:
            limit_per_minute = 10
            cache_key = f"rate_limit:anon:{self._get_client_ip(request)}"

        # Check cache
        current_count = cache.get(cache_key, 0)
        ttl = cache.ttl(cache_key) if hasattr(cache, 'ttl') else 60

        if current_count >= limit_per_minute:
            return {
                'exceeded': True,
                'limit': limit_per_minute,
                'remaining': 0,
                'reset': ttl if ttl > 0 else 60,
            }

        # Increment counter
        if current_count == 0:
            cache.set(cache_key, 1, timeout=60)
        else:
            cache.incr(cache_key)

        return {
            'exceeded': False,
            'limit': limit_per_minute,
            'remaining': limit_per_minute - current_count - 1,
            'reset': ttl if ttl > 0 else 60,
        }

    def _get_api_key(self, request):
        """Extract API key from request."""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return request.GET.get('api_key', '')

    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class SecurityHeadersMiddleware:
    """
    Middleware for adding security headers.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        return response
