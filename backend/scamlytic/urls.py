"""
URL configuration for Scamlytic API.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from apps.core.views import HealthCheckView, APIRootView

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # API Root
    path('', APIRootView.as_view(), name='api-root'),
    path('health/', HealthCheckView.as_view(), name='health-check'),

    # API v1 endpoints
    path('v1/', include([
        # Core
        path('', include('apps.core.urls')),

        # Analysis endpoints
        path('analyze/', include('apps.analysis.urls')),

        # User management
        path('users/', include('apps.users.urls')),

        # Reports
        path('reports/', include('apps.reports.urls')),

        # Integrations & Webhooks
        path('integrations/', include('apps.integrations.urls')),
    ])),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
