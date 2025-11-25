"""
Custom authentication classes for Scamlytic API.
"""

from rest_framework import authentication
from rest_framework import exceptions
from django.utils import timezone

from .models import APIKey


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication using API keys.

    Clients should authenticate by passing the API key in the Authorization header:
        Authorization: Bearer scam_xxxxxxxxxxxx
    """

    keyword = 'Bearer'

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header:
            # Try query parameter as fallback
            api_key = request.GET.get('api_key', '')
            if not api_key:
                return None
        else:
            parts = auth_header.split()

            if len(parts) != 2:
                return None

            if parts[0].lower() != self.keyword.lower():
                return None

            api_key = parts[1]

        # Validate API key format
        if not api_key.startswith(APIKey.PREFIX):
            return None

        # Look up API key
        try:
            key_obj = APIKey.objects.select_related('user').get(
                key=api_key,
                is_active=True
            )
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key')

        # Check if key is valid
        if not key_obj.is_valid():
            raise exceptions.AuthenticationFailed('API key is expired or revoked')

        # Check if user is active
        if not key_obj.user.is_active:
            raise exceptions.AuthenticationFailed('User account is disabled')

        # Check IP restrictions
        client_ip = self._get_client_ip(request)
        if key_obj.allowed_ips and client_ip not in key_obj.allowed_ips:
            raise exceptions.AuthenticationFailed('IP address not allowed for this API key')

        # Check domain restrictions
        referer = request.META.get('HTTP_REFERER', '')
        if key_obj.allowed_domains and referer:
            from urllib.parse import urlparse
            referer_domain = urlparse(referer).netloc
            if referer_domain and referer_domain not in key_obj.allowed_domains:
                raise exceptions.AuthenticationFailed('Domain not allowed for this API key')

        # Record usage
        key_obj.record_usage(ip_address=client_ip)

        # Return user and key
        return (key_obj.user, key_obj)

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def authenticate_header(self, request):
        return f'{self.keyword} realm="api"'
