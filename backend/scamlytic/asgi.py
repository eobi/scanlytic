"""
ASGI config for Scamlytic API.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scamlytic.settings')

application = get_asgi_application()
