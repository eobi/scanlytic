"""
Views for Integrations API.
"""

from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Webhook, WebhookDelivery, ExternalIntegration, IntegrationHealth
from .serializers import (
    WebhookSerializer, WebhookCreateSerializer,
    WebhookDeliverySerializer, ExternalIntegrationSerializer,
    IntegrationHealthSerializer
)


class WebhookListCreateView(generics.ListCreateAPIView):
    """
    List and create webhooks.

    GET/POST /v1/integrations/webhooks/
    """
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return WebhookCreateSerializer
        return WebhookSerializer

    def get_queryset(self):
        return Webhook.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class WebhookDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Get, update, or delete a webhook.

    GET/PUT/DELETE /v1/integrations/webhooks/{id}/
    """
    serializer_class = WebhookSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Webhook.objects.filter(user=self.request.user)


class WebhookDeliveryListView(generics.ListAPIView):
    """
    List webhook deliveries.

    GET /v1/integrations/webhooks/{webhook_id}/deliveries/
    """
    serializer_class = WebhookDeliverySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        webhook_id = self.kwargs.get('webhook_id')
        return WebhookDelivery.objects.filter(
            webhook__user=self.request.user,
            webhook_id=webhook_id
        )[:50]


class WebhookTestView(views.APIView):
    """
    Test a webhook endpoint.

    POST /v1/integrations/webhooks/{id}/test/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            webhook = Webhook.objects.get(pk=pk, user=request.user)
        except Webhook.DoesNotExist:
            return Response(
                {'error': 'Webhook not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        from .services import WebhookService
        service = WebhookService()

        result = service.test_webhook(webhook)

        return Response(result)


class ExternalIntegrationListCreateView(generics.ListCreateAPIView):
    """
    List and create external integrations.

    GET/POST /v1/integrations/external/
    """
    serializer_class = ExternalIntegrationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ExternalIntegration.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ExternalIntegrationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Get, update, or delete an external integration.
    """
    serializer_class = ExternalIntegrationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ExternalIntegration.objects.filter(user=self.request.user)


class IntegrationHealthListView(generics.ListAPIView):
    """
    List health status of all integrations.

    GET /v1/integrations/health/
    """
    serializer_class = IntegrationHealthSerializer
    permission_classes = [IsAuthenticated]
    queryset = IntegrationHealth.objects.all()
