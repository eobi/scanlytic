"""
WSGI config for Scamlytic API.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scamlytic.settings')

application = get_wsgi_application()
