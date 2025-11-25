"""
URL patterns for Integrations API.
"""

from django.urls import path

from .views import (
    WebhookListCreateView, WebhookDetailView,
    WebhookDeliveryListView, WebhookTestView,
    ExternalIntegrationListCreateView, ExternalIntegrationDetailView,
    IntegrationHealthListView
)

app_name = 'integrations'

urlpatterns = [
    # Webhooks
    path('webhooks/', WebhookListCreateView.as_view(), name='webhook-list'),
    path('webhooks/<uuid:pk>/', WebhookDetailView.as_view(), name='webhook-detail'),
    path('webhooks/<uuid:pk>/test/', WebhookTestView.as_view(), name='webhook-test'),
    path('webhooks/<uuid:webhook_id>/deliveries/', WebhookDeliveryListView.as_view(), name='webhook-deliveries'),

    # External integrations
    path('external/', ExternalIntegrationListCreateView.as_view(), name='external-list'),
    path('external/<uuid:pk>/', ExternalIntegrationDetailView.as_view(), name='external-detail'),

    # Health
    path('health/', IntegrationHealthListView.as_view(), name='health-list'),
]
