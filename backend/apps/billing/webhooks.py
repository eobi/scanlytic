"""
Stripe Webhook Handlers.

Process incoming Stripe webhook events for subscription lifecycle,
payment processing, and invoice management.
"""

import logging
from datetime import datetime

import stripe
from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone

from .models import (
    Customer, Subscription, Invoice, WebhookEvent,
    SubscriptionPlan
)
from .stripe_service import stripe_service

logger = logging.getLogger('scamlytic.billing.webhooks')


class WebhookHandler:
    """
    Handler class for Stripe webhook events.
    """

    def __init__(self):
        self.handlers = {
            # Customer events
            'customer.created': self.handle_customer_created,
            'customer.updated': self.handle_customer_updated,
            'customer.deleted': self.handle_customer_deleted,

            # Subscription events
            'customer.subscription.created': self.handle_subscription_created,
            'customer.subscription.updated': self.handle_subscription_updated,
            'customer.subscription.deleted': self.handle_subscription_deleted,
            'customer.subscription.trial_will_end': self.handle_trial_will_end,

            # Invoice events
            'invoice.created': self.handle_invoice_created,
            'invoice.updated': self.handle_invoice_updated,
            'invoice.paid': self.handle_invoice_paid,
            'invoice.payment_failed': self.handle_invoice_payment_failed,
            'invoice.finalized': self.handle_invoice_finalized,

            # Payment events
            'payment_intent.succeeded': self.handle_payment_succeeded,
            'payment_intent.payment_failed': self.handle_payment_failed,

            # Checkout events
            'checkout.session.completed': self.handle_checkout_completed,

            # Payment method events
            'payment_method.attached': self.handle_payment_method_attached,
            'payment_method.detached': self.handle_payment_method_detached,
        }

    def handle_event(self, event):
        """
        Route event to appropriate handler.

        Args:
            event: Stripe event object

        Returns:
            True if handled successfully
        """
        event_type = event['type']
        handler = self.handlers.get(event_type)

        if handler:
            try:
                handler(event)
                return True
            except Exception as e:
                logger.error(f"Error handling {event_type}: {e}")
                raise
        else:
            logger.info(f"Unhandled event type: {event_type}")
            return True

    # =========================================================================
    # Customer Handlers
    # =========================================================================

    def handle_customer_created(self, event):
        """Handle customer.created event."""
        customer_data = event['data']['object']
        logger.info(f"Customer created in Stripe: {customer_data['id']}")
        # Customer typically created via our API, so this is for sync
        pass

    def handle_customer_updated(self, event):
        """Handle customer.updated event."""
        customer_data = event['data']['object']

        try:
            customer = Customer.objects.get(
                stripe_customer_id=customer_data['id']
            )

            # Update local record with Stripe data
            customer.email = customer_data.get('email', customer.email)
            customer.name = customer_data.get('name', '') or customer.name
            customer.phone = customer_data.get('phone', '') or customer.phone
            customer.balance = customer_data.get('balance', 0)
            customer.delinquent = customer_data.get('delinquent', False)

            # Update address if present
            address = customer_data.get('address') or {}
            if address:
                customer.address_line1 = address.get('line1', '')
                customer.address_line2 = address.get('line2', '')
                customer.city = address.get('city', '')
                customer.state = address.get('state', '')
                customer.postal_code = address.get('postal_code', '')
                customer.country = address.get('country', '')

            customer.save()
            logger.info(f"Updated customer: {customer.stripe_customer_id}")

        except Customer.DoesNotExist:
            logger.warning(f"Customer not found: {customer_data['id']}")

    def handle_customer_deleted(self, event):
        """Handle customer.deleted event."""
        customer_data = event['data']['object']

        try:
            customer = Customer.objects.get(
                stripe_customer_id=customer_data['id']
            )
            # Don't delete, just log - user record remains
            logger.info(f"Customer deleted in Stripe: {customer.stripe_customer_id}")

        except Customer.DoesNotExist:
            pass

    # =========================================================================
    # Subscription Handlers
    # =========================================================================

    def handle_subscription_created(self, event):
        """Handle customer.subscription.created event."""
        sub_data = event['data']['object']
        logger.info(f"Subscription created: {sub_data['id']}")

        # Subscription typically created via our API, but sync if needed
        try:
            subscription = Subscription.objects.get(
                stripe_subscription_id=sub_data['id']
            )
            self._update_subscription_from_stripe(subscription, sub_data)
        except Subscription.DoesNotExist:
            # Create new subscription record if not found
            self._create_subscription_from_stripe(sub_data)

    def handle_subscription_updated(self, event):
        """Handle customer.subscription.updated event."""
        sub_data = event['data']['object']

        try:
            subscription = Subscription.objects.get(
                stripe_subscription_id=sub_data['id']
            )
            self._update_subscription_from_stripe(subscription, sub_data)
            logger.info(f"Updated subscription: {subscription.stripe_subscription_id}")

            # Update user's plan if status changed
            if subscription.is_active:
                subscription.customer.user.plan = subscription.plan.tier
                subscription.customer.user.save(update_fields=['plan'])
            elif sub_data['status'] == 'canceled':
                subscription.customer.user.plan = 'free'
                subscription.customer.user.save(update_fields=['plan'])

        except Subscription.DoesNotExist:
            logger.warning(f"Subscription not found: {sub_data['id']}")

    def handle_subscription_deleted(self, event):
        """Handle customer.subscription.deleted event."""
        sub_data = event['data']['object']

        try:
            subscription = Subscription.objects.get(
                stripe_subscription_id=sub_data['id']
            )
            subscription.status = 'canceled'
            subscription.ended_at = timezone.now()
            subscription.save()

            # Downgrade user to free plan
            subscription.customer.user.plan = 'free'
            subscription.customer.user.save(update_fields=['plan'])

            logger.info(f"Subscription deleted: {subscription.stripe_subscription_id}")

        except Subscription.DoesNotExist:
            logger.warning(f"Subscription not found: {sub_data['id']}")

    def handle_trial_will_end(self, event):
        """Handle customer.subscription.trial_will_end event."""
        sub_data = event['data']['object']

        try:
            subscription = Subscription.objects.get(
                stripe_subscription_id=sub_data['id']
            )

            # Send notification to user about trial ending
            # This would integrate with your notification system
            logger.info(
                f"Trial ending for subscription: {subscription.stripe_subscription_id}"
            )

            # TODO: Send email notification
            # send_trial_ending_email(subscription.customer.user)

        except Subscription.DoesNotExist:
            logger.warning(f"Subscription not found: {sub_data['id']}")

    def _update_subscription_from_stripe(self, subscription, stripe_data):
        """Update subscription model from Stripe data."""
        subscription.status = stripe_data['status']
        subscription.cancel_at_period_end = stripe_data.get('cancel_at_period_end', False)

        if stripe_data.get('current_period_start'):
            subscription.current_period_start = datetime.fromtimestamp(
                stripe_data['current_period_start'], tz=timezone.utc
            )
        if stripe_data.get('current_period_end'):
            subscription.current_period_end = datetime.fromtimestamp(
                stripe_data['current_period_end'], tz=timezone.utc
            )
        if stripe_data.get('trial_start'):
            subscription.trial_start = datetime.fromtimestamp(
                stripe_data['trial_start'], tz=timezone.utc
            )
        if stripe_data.get('trial_end'):
            subscription.trial_end = datetime.fromtimestamp(
                stripe_data['trial_end'], tz=timezone.utc
            )
        if stripe_data.get('canceled_at'):
            subscription.canceled_at = datetime.fromtimestamp(
                stripe_data['canceled_at'], tz=timezone.utc
            )
        if stripe_data.get('ended_at'):
            subscription.ended_at = datetime.fromtimestamp(
                stripe_data['ended_at'], tz=timezone.utc
            )

        subscription.save()

    def _create_subscription_from_stripe(self, stripe_data):
        """Create subscription from Stripe data."""
        try:
            customer = Customer.objects.get(
                stripe_customer_id=stripe_data['customer']
            )
        except Customer.DoesNotExist:
            logger.warning(f"Customer not found: {stripe_data['customer']}")
            return None

        # Find plan from price ID
        price_id = stripe_data['items']['data'][0]['price']['id']
        plan = SubscriptionPlan.objects.filter(
            stripe_price_id_monthly=price_id
        ).first() or SubscriptionPlan.objects.filter(
            stripe_price_id_yearly=price_id
        ).first()

        if not plan:
            logger.warning(f"Plan not found for price: {price_id}")
            return None

        subscription = Subscription.objects.create(
            customer=customer,
            plan=plan,
            stripe_subscription_id=stripe_data['id'],
            stripe_price_id=price_id,
            status=stripe_data['status'],
        )
        self._update_subscription_from_stripe(subscription, stripe_data)
        return subscription

    # =========================================================================
    # Invoice Handlers
    # =========================================================================

    def handle_invoice_created(self, event):
        """Handle invoice.created event."""
        invoice_data = event['data']['object']
        stripe_service.sync_invoice(type('obj', (object,), invoice_data)())
        logger.info(f"Invoice created: {invoice_data['id']}")

    def handle_invoice_updated(self, event):
        """Handle invoice.updated event."""
        invoice_data = event['data']['object']
        stripe_service.sync_invoice(type('obj', (object,), invoice_data)())
        logger.info(f"Invoice updated: {invoice_data['id']}")

    def handle_invoice_paid(self, event):
        """Handle invoice.paid event."""
        invoice_data = event['data']['object']

        try:
            invoice = Invoice.objects.get(
                stripe_invoice_id=invoice_data['id']
            )
            invoice.status = 'paid'
            invoice.paid_at = timezone.now()
            invoice.amount_paid = invoice_data.get('amount_paid', 0)
            invoice.amount_remaining = 0
            invoice.save()

            logger.info(f"Invoice paid: {invoice.stripe_invoice_id}")

        except Invoice.DoesNotExist:
            # Create if doesn't exist
            stripe_service.sync_invoice(type('obj', (object,), invoice_data)())

    def handle_invoice_payment_failed(self, event):
        """Handle invoice.payment_failed event."""
        invoice_data = event['data']['object']

        try:
            invoice = Invoice.objects.get(
                stripe_invoice_id=invoice_data['id']
            )

            # Update subscription status if recurring payment failed
            if invoice.subscription:
                invoice.subscription.status = 'past_due'
                invoice.subscription.save()

            logger.warning(f"Invoice payment failed: {invoice.stripe_invoice_id}")

            # TODO: Send payment failed notification
            # send_payment_failed_email(invoice.customer.user)

        except Invoice.DoesNotExist:
            logger.warning(f"Invoice not found: {invoice_data['id']}")

    def handle_invoice_finalized(self, event):
        """Handle invoice.finalized event."""
        invoice_data = event['data']['object']
        stripe_service.sync_invoice(type('obj', (object,), invoice_data)())
        logger.info(f"Invoice finalized: {invoice_data['id']}")

    # =========================================================================
    # Payment Handlers
    # =========================================================================

    def handle_payment_succeeded(self, event):
        """Handle payment_intent.succeeded event."""
        payment_data = event['data']['object']
        logger.info(f"Payment succeeded: {payment_data['id']}")
        # Payment success typically handled via invoice.paid

    def handle_payment_failed(self, event):
        """Handle payment_intent.payment_failed event."""
        payment_data = event['data']['object']
        logger.warning(f"Payment failed: {payment_data['id']}")

        # Get error details
        error = payment_data.get('last_payment_error', {})
        error_message = error.get('message', 'Unknown error')

        # TODO: Notify customer about payment failure
        # send_payment_failed_email(customer, error_message)

    def handle_checkout_completed(self, event):
        """Handle checkout.session.completed event."""
        session_data = event['data']['object']
        logger.info(f"Checkout completed: {session_data['id']}")

        # If subscription checkout, subscription webhook handles it
        if session_data.get('subscription'):
            pass

    # =========================================================================
    # Payment Method Handlers
    # =========================================================================

    def handle_payment_method_attached(self, event):
        """Handle payment_method.attached event."""
        pm_data = event['data']['object']
        logger.info(f"Payment method attached: {pm_data['id']}")
        # Usually handled via our API attach flow

    def handle_payment_method_detached(self, event):
        """Handle payment_method.detached event."""
        pm_data = event['data']['object']
        logger.info(f"Payment method detached: {pm_data['id']}")

        from .models import PaymentMethod
        try:
            PaymentMethod.objects.filter(
                stripe_payment_method_id=pm_data['id']
            ).delete()
        except Exception:
            pass


# Singleton handler
webhook_handler = WebhookHandler()


@csrf_exempt
@require_POST
def stripe_webhook(request):
    """
    Stripe webhook endpoint.

    Verifies webhook signature and dispatches to handlers.
    """
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)

    if not webhook_secret:
        logger.error("Stripe webhook secret not configured")
        return HttpResponse(status=500)

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        return HttpResponse(status=400)

    # Check for duplicate event
    event_id = event['id']
    if WebhookEvent.objects.filter(stripe_event_id=event_id).exists():
        logger.info(f"Duplicate event ignored: {event_id}")
        return HttpResponse(status=200)

    # Log event
    webhook_event = WebhookEvent.objects.create(
        stripe_event_id=event_id,
        event_type=event['type'],
        api_version=event.get('api_version', ''),
        data=event['data'],
        event_created_at=datetime.fromtimestamp(
            event['created'], tz=timezone.utc
        ),
    )

    # Process event
    try:
        webhook_handler.handle_event(event)
        webhook_event.processed = True
        webhook_event.processed_at = timezone.now()
        webhook_event.save()
    except Exception as e:
        logger.exception(f"Error processing webhook: {e}")
        webhook_event.processing_error = str(e)
        webhook_event.retry_count += 1
        webhook_event.save()
        return HttpResponse(status=500)

    return HttpResponse(status=200)
