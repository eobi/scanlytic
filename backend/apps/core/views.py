"""
Core views for Scamlytic API.
"""

from django.db import connection
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status


class HealthCheckView(APIView):
    """
    Health check endpoint for monitoring.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        health_status = {
            'status': 'healthy',
            'version': '1.0.0',
            'services': {}
        }

        # Check database
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
            health_status['services']['database'] = 'healthy'
        except Exception as e:
            health_status['services']['database'] = 'unhealthy'
            health_status['status'] = 'degraded'

        # Check cache
        try:
            cache.set('health_check', 'ok', timeout=10)
            if cache.get('health_check') == 'ok':
                health_status['services']['cache'] = 'healthy'
            else:
                health_status['services']['cache'] = 'unhealthy'
                health_status['status'] = 'degraded'
        except Exception:
            health_status['services']['cache'] = 'unhealthy'
            health_status['status'] = 'degraded'

        status_code = status.HTTP_200_OK if health_status['status'] == 'healthy' else status.HTTP_503_SERVICE_UNAVAILABLE

        return Response(health_status, status=status_code)


class APIRootView(APIView):
    """
    API root endpoint with documentation.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({
            'name': 'Scamlytic API',
            'version': 'v1',
            'description': 'AI-Powered Scam Detection Platform',
            'documentation': 'https://docs.scamlytic.com',
            'endpoints': {
                'analyze': {
                    'message': '/v1/analyze/message/',
                    'url': '/v1/analyze/url/',
                    'phone': '/v1/analyze/phone/',
                    'profile': '/v1/analyze/profile/',
                },
                'reports': '/v1/reports/',
                'users': {
                    'register': '/v1/users/register/',
                    'login': '/v1/users/login/',
                    'profile': '/v1/users/profile/',
                    'api-keys': '/v1/users/api-keys/',
                },
                'health': '/health/',
            },
            'rate_limits': {
                'free': '50 requests/day',
                'pro': '10,000 requests/day',
                'developer': '10,000 requests/day',
                'business': '100,000 requests/day',
            },
        })
