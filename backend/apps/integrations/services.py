"""
Integration Services.
"""

import hmac
import hashlib
import json
import logging
import time
from typing import Dict, Any

import requests
from django.utils import timezone
from django.conf import settings

from .models import Webhook, WebhookDelivery, IntegrationHealth

logger = logging.getLogger('scamlytic.integrations')


class WebhookService:
    """
    Service for webhook management and delivery.
    """

    def trigger_event(
        self,
        user,
        event: str,
        payload: Dict[str, Any]
    ):
        """
        Trigger webhooks for a specific event.
        """
        webhooks = Webhook.objects.filter(
            user=user,
            is_active=True
        )

        for webhook in webhooks:
            if event in webhook.events or '*' in webhook.events:
                self._deliver_webhook(webhook, event, payload)

    def _deliver_webhook(
        self,
        webhook: Webhook,
        event: str,
        payload: Dict[str, Any]
    ):
        """
        Deliver a webhook notification.
        """
        # Create delivery record
        delivery = WebhookDelivery.objects.create(
            webhook=webhook,
            event=event,
            payload=payload,
            status='pending'
        )

        # Prepare request
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Scamlytic-Webhook/1.0',
            'X-Scamlytic-Event': event,
            'X-Scamlytic-Delivery': str(delivery.id),
        }

        # Add signature if secret is set
        if webhook.secret:
            body = json.dumps(payload)
            signature = hmac.new(
                webhook.secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-Scamlytic-Signature'] = f'sha256={signature}'

        # Attempt delivery
        start_time = time.time()
        try:
            response = requests.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=webhook.timeout_seconds,
                verify=webhook.verify_ssl
            )

            duration = int((time.time() - start_time) * 1000)

            # Update delivery record
            delivery.status = 'delivered' if response.ok else 'failed'
            delivery.response_status_code = response.status_code
            delivery.response_body = response.text[:1000]
            delivery.duration_ms = duration
            delivery.attempt_count = 1

            if not response.ok:
                delivery.error_message = f"HTTP {response.status_code}"

            delivery.save()

            # Update webhook stats
            webhook.total_deliveries += 1
            webhook.last_triggered_at = timezone.now()

            if response.ok:
                webhook.successful_deliveries += 1
                webhook.last_success_at = timezone.now()
            else:
                webhook.failed_deliveries += 1
                webhook.last_failure_at = timezone.now()
                webhook.last_failure_reason = f"HTTP {response.status_code}"

            webhook.save()

        except requests.RequestException as e:
            duration = int((time.time() - start_time) * 1000)

            delivery.status = 'failed'
            delivery.duration_ms = duration
            delivery.attempt_count = 1
            delivery.error_message = str(e)
            delivery.save()

            webhook.total_deliveries += 1
            webhook.failed_deliveries += 1
            webhook.last_triggered_at = timezone.now()
            webhook.last_failure_at = timezone.now()
            webhook.last_failure_reason = str(e)
            webhook.save()

            logger.error(f"Webhook delivery failed: {e}")

    def test_webhook(self, webhook: Webhook) -> Dict[str, Any]:
        """
        Test a webhook endpoint.
        """
        test_payload = {
            'event': 'test',
            'data': {
                'message': 'This is a test webhook from Scamlytic',
                'timestamp': timezone.now().isoformat(),
            }
        }

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Scamlytic-Webhook/1.0',
            'X-Scamlytic-Event': 'test',
        }

        if webhook.secret:
            body = json.dumps(test_payload)
            signature = hmac.new(
                webhook.secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-Scamlytic-Signature'] = f'sha256={signature}'

        try:
            start_time = time.time()
            response = requests.post(
                webhook.url,
                json=test_payload,
                headers=headers,
                timeout=10,
                verify=webhook.verify_ssl
            )
            duration = int((time.time() - start_time) * 1000)

            return {
                'success': response.ok,
                'status_code': response.status_code,
                'duration_ms': duration,
                'response': response.text[:500] if not response.ok else None,
            }

        except requests.RequestException as e:
            return {
                'success': False,
                'error': str(e),
            }


class IntegrationHealthService:
    """
    Service for monitoring third-party integration health.
    """

    HEALTH_CHECKS = {
        'virustotal': {
            'url': 'https://www.virustotal.com/api/v3/urls',
            'method': 'HEAD',
        },
        'google_safebrowsing': {
            'url': 'https://safebrowsing.googleapis.com/$discovery/rest',
            'method': 'GET',
        },
        'phishtank': {
            'url': 'https://checkurl.phishtank.com/checkurl/',
            'method': 'HEAD',
        },
        'urlhaus': {
            'url': 'https://urlhaus-api.abuse.ch/v1/',
            'method': 'GET',
        },
    }

    def check_all(self):
        """
        Check health of all integrations.
        """
        results = {}
        for service, config in self.HEALTH_CHECKS.items():
            results[service] = self._check_service(service, config)
        return results

    def _check_service(self, service: str, config: Dict) -> Dict[str, Any]:
        """
        Check a single service.
        """
        try:
            start_time = time.time()
            response = requests.request(
                config['method'],
                config['url'],
                timeout=10,
                headers={'User-Agent': 'Scamlytic-HealthCheck/1.0'}
            )
            duration = int((time.time() - start_time) * 1000)

            is_healthy = response.status_code < 500

            # Update or create health record
            health, _ = IntegrationHealth.objects.update_or_create(
                service_name=service,
                defaults={
                    'display_name': service.replace('_', ' ').title(),
                    'is_healthy': is_healthy,
                    'response_time_ms': duration,
                    'error_message': '' if is_healthy else f"HTTP {response.status_code}",
                    'consecutive_failures': 0 if is_healthy else 1,
                }
            )

            return {
                'is_healthy': is_healthy,
                'response_time_ms': duration,
                'status_code': response.status_code,
            }

        except requests.RequestException as e:
            # Update health record
            health, created = IntegrationHealth.objects.get_or_create(
                service_name=service,
                defaults={'display_name': service.replace('_', ' ').title()}
            )

            if not created:
                health.consecutive_failures += 1

            health.is_healthy = False
            health.error_message = str(e)
            health.save()

            return {
                'is_healthy': False,
                'error': str(e),
            }
