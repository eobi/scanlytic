"""
Custom exceptions and exception handler for Scamlytic API.
"""

from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger('scamlytic')


class ScamlyticException(Exception):
    """Base exception for Scamlytic API."""
    default_message = "An error occurred"
    default_code = "error"
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, message=None, code=None, details=None):
        self.message = message or self.default_message
        self.code = code or self.default_code
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(ScamlyticException):
    """Validation error for invalid input."""
    default_message = "Validation failed"
    default_code = "validation_error"
    status_code = status.HTTP_400_BAD_REQUEST


class AuthenticationError(ScamlyticException):
    """Authentication error."""
    default_message = "Authentication failed"
    default_code = "authentication_error"
    status_code = status.HTTP_401_UNAUTHORIZED


class AuthorizationError(ScamlyticException):
    """Authorization/permission error."""
    default_message = "You don't have permission to perform this action"
    default_code = "authorization_error"
    status_code = status.HTTP_403_FORBIDDEN


class NotFoundError(ScamlyticException):
    """Resource not found error."""
    default_message = "Resource not found"
    default_code = "not_found"
    status_code = status.HTTP_404_NOT_FOUND


class RateLimitError(ScamlyticException):
    """Rate limit exceeded error."""
    default_message = "Rate limit exceeded"
    default_code = "rate_limit_exceeded"
    status_code = status.HTTP_429_TOO_MANY_REQUESTS


class QuotaExceededError(ScamlyticException):
    """Quota exceeded error."""
    default_message = "API quota exceeded for your plan"
    default_code = "quota_exceeded"
    status_code = status.HTTP_429_TOO_MANY_REQUESTS


class IntegrationError(ScamlyticException):
    """Third-party integration error."""
    default_message = "External service error"
    default_code = "integration_error"
    status_code = status.HTTP_502_BAD_GATEWAY


class AnalysisError(ScamlyticException):
    """Analysis processing error."""
    default_message = "Analysis could not be completed"
    default_code = "analysis_error"
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


class ContentTooLargeError(ScamlyticException):
    """Content size limit exceeded."""
    default_message = "Content exceeds maximum allowed size"
    default_code = "content_too_large"
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


def custom_exception_handler(exc, context):
    """
    Custom exception handler for consistent API error responses.
    """
    # Handle Scamlytic exceptions
    if isinstance(exc, ScamlyticException):
        logger.warning(
            f"API Error: {exc.code} - {exc.message}",
            extra={
                'code': exc.code,
                'details': exc.details,
                'view': context.get('view').__class__.__name__ if context.get('view') else None,
            }
        )
        return Response(
            {
                'error': {
                    'code': exc.code,
                    'message': exc.message,
                    'details': exc.details,
                }
            },
            status=exc.status_code
        )

    # Get standard DRF response
    response = exception_handler(exc, context)

    if response is not None:
        # Standardize error format
        error_data = {
            'error': {
                'code': 'api_error',
                'message': 'An error occurred',
                'details': {},
            }
        }

        if hasattr(response, 'data'):
            if isinstance(response.data, dict):
                if 'detail' in response.data:
                    error_data['error']['message'] = str(response.data['detail'])
                else:
                    error_data['error']['details'] = response.data
            elif isinstance(response.data, list):
                error_data['error']['details'] = {'errors': response.data}

        # Set appropriate error codes based on status
        status_codes = {
            400: 'bad_request',
            401: 'unauthorized',
            403: 'forbidden',
            404: 'not_found',
            405: 'method_not_allowed',
            429: 'rate_limit_exceeded',
            500: 'internal_error',
        }
        error_data['error']['code'] = status_codes.get(
            response.status_code, 'api_error'
        )

        response.data = error_data

    return response
