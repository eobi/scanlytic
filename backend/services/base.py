"""
Base service classes and utilities.
"""

import logging
import hashlib
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from functools import wraps

import requests
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger('scamlytic.services')


class ServiceException(Exception):
    """Base exception for service errors."""
    pass


class RateLimitException(ServiceException):
    """Rate limit exceeded for external API."""
    pass


class APIKeyException(ServiceException):
    """Missing or invalid API key."""
    pass


class BaseService(ABC):
    """
    Base class for all external service integrations.
    """

    service_name: str = "base"
    base_url: str = ""
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Scamlytic/1.0 (Security Analysis Platform)'
        })

    def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """Make HTTP request with retry logic."""
        kwargs.setdefault('timeout', self.timeout)

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(method, url, **kwargs)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    if attempt < self.max_retries - 1:
                        logger.warning(
                            f"{self.service_name}: Rate limited, waiting {retry_after}s"
                        )
                        time.sleep(min(retry_after, 120))
                        continue
                    raise RateLimitException(
                        f"{self.service_name} rate limit exceeded"
                    )

                return response

            except requests.RequestException as e:
                logger.warning(
                    f"{self.service_name}: Request failed (attempt {attempt + 1}): {e}"
                )
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                    continue
                raise ServiceException(f"{self.service_name} request failed: {e}")

        raise ServiceException(f"{self.service_name} max retries exceeded")

    def _get_cache_key(self, *args) -> str:
        """Generate cache key from arguments."""
        key_data = f"{self.service_name}:" + ":".join(str(a) for a in args)
        return hashlib.md5(key_data.encode()).hexdigest()

    def _get_cached(self, cache_key: str) -> Optional[Any]:
        """Get cached result."""
        return cache.get(cache_key)

    def _set_cached(self, cache_key: str, value: Any, timeout: int = 3600):
        """Set cached result."""
        cache.set(cache_key, value, timeout=timeout)

    @abstractmethod
    def analyze(self, *args, **kwargs) -> Dict[str, Any]:
        """Perform analysis. Must be implemented by subclasses."""
        pass

    def health_check(self) -> bool:
        """Check if the service is available."""
        return True


def cached_result(timeout: int = 3600):
    """Decorator for caching service results."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Generate cache key
            cache_key = self._get_cache_key(func.__name__, *args)

            # Check cache
            cached = self._get_cached(cache_key)
            if cached is not None:
                logger.debug(f"{self.service_name}: Cache hit for {func.__name__}")
                return cached

            # Call function
            result = func(self, *args, **kwargs)

            # Cache result
            if result is not None:
                self._set_cached(cache_key, result, timeout)

            return result
        return wrapper
    return decorator


def require_api_key(key_setting: str):
    """Decorator to check API key is configured."""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            api_key = getattr(settings, key_setting, '')
            if not api_key:
                logger.warning(
                    f"{self.service_name}: API key not configured ({key_setting})"
                )
                return {
                    'available': False,
                    'error': f'{key_setting} not configured'
                }
            return func(self, *args, **kwargs)
        return wrapper
    return decorator
