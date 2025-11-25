"""
Stripe Service for Scamlytic Billing.

Handles all Stripe API interactions for subscriptions, payments,
customers, and usage-based billing.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from decimal import Decimal
from datetime import datetime, timedelta

import stripe
from django.conf import settings
from django.utils import timezone
from django.db import transaction

from .models import (
    Customer, Subscription, SubscriptionPlan, Invoice,
    PaymentMethod, UsageRecord, UsageSummary, Coupon, WebhookEvent
)

logger = logging.getLogger('scamlytic.billing.stripe')


class StripeService:
    """
    Stripe API integration service.
    """

    def __init__(self):
        self.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
        self.webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
        self.publishable_key = getattr(settings, 'STRIPE_PUBLISHABLE_KEY', None)

        if self.api_key:
            stripe.api_key = self.api_key

    def is_configured(self) -> bool:
        """Check if Stripe is properly configured."""
        return bool(self.api_key)

    # =========================================================================
    # Customer Management
    # =========================================================================

    def create_customer(
        self,
        user,
        email: str,
        name: str = '',
        metadata: Dict[str, Any] = None
    ) -> Customer:
        """
        Create a new Stripe customer and local record.

        Args:
            user: Django user instance
            email: Customer email
            name: Customer name
            metadata: Additional metadata

        Returns:
            Customer model instance
        """
        try:
            # Create Stripe customer
            stripe_customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={
                    'user_id': str(user.id),
                    'platform': 'scamlytic',
                    **(metadata or {})
                }
            )

            # Create local customer record
            customer = Customer.objects.create(
                user=user,
                stripe_customer_id=stripe_customer.id,
                email=email,
                name=name,
                metadata=metadata or {}
            )

            logger.info(f"Created Stripe customer: {stripe_customer.id}")
            return customer

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating customer: {e}")
            raise

    def get_or_create_customer(self, user) -> Customer:
        """Get existing customer or create new one."""
        try:
            return Customer.objects.get(user=user)
        except Customer.DoesNotExist:
            return self.create_customer(
                user=user,
                email=user.email,
                name=getattr(user, 'full_name', '') or user.email
            )

    def update_customer(
        self,
        customer: Customer,
        **kwargs
    ) -> Customer:
        """Update customer details in Stripe and locally."""
        try:
            # Update Stripe
            stripe_data = {}
            if 'email' in kwargs:
                stripe_data['email'] = kwargs['email']
            if 'name' in kwargs:
                stripe_data['name'] = kwargs['name']
            if 'phone' in kwargs:
                stripe_data['phone'] = kwargs['phone']
            if 'address' in kwargs:
                stripe_data['address'] = kwargs['address']

            if stripe_data:
                stripe.Customer.modify(customer.stripe_customer_id, **stripe_data)

            # Update local record
            for key, value in kwargs.items():
                if hasattr(customer, key):
                    setattr(customer, key, value)
            customer.save()

            return customer

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error updating customer: {e}")
            raise

    def delete_customer(self, customer: Customer) -> bool:
        """Delete customer from Stripe (marks as deleted)."""
        try:
            stripe.Customer.delete(customer.stripe_customer_id)
            logger.info(f"Deleted Stripe customer: {customer.stripe_customer_id}")
            return True
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error deleting customer: {e}")
            return False

    # =========================================================================
    # Payment Methods
    # =========================================================================

    def create_setup_intent(self, customer: Customer) -> Dict[str, Any]:
        """
        Create a SetupIntent for collecting payment method.

        Returns client_secret for frontend to complete setup.
        """
        try:
            setup_intent = stripe.SetupIntent.create(
                customer=customer.stripe_customer_id,
                payment_method_types=['card'],
                metadata={'customer_id': str(customer.id)}
            )

            return {
                'client_secret': setup_intent.client_secret,
                'setup_intent_id': setup_intent.id,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating SetupIntent: {e}")
            raise

    def attach_payment_method(
        self,
        customer: Customer,
        payment_method_id: str,
        set_as_default: bool = True
    ) -> PaymentMethod:
        """Attach a payment method to customer."""
        try:
            # Attach to customer in Stripe
            stripe.PaymentMethod.attach(
                payment_method_id,
                customer=customer.stripe_customer_id
            )

            # Get payment method details
            pm = stripe.PaymentMethod.retrieve(payment_method_id)

            # Set as default if requested
            if set_as_default:
                stripe.Customer.modify(
                    customer.stripe_customer_id,
                    invoice_settings={'default_payment_method': payment_method_id}
                )

                # Update customer record
                if pm.type == 'card':
                    customer.default_payment_method_id = payment_method_id
                    customer.payment_method_type = 'card'
                    customer.card_last4 = pm.card.last4
                    customer.card_brand = pm.card.brand
                    customer.card_exp_month = pm.card.exp_month
                    customer.card_exp_year = pm.card.exp_year
                    customer.save()

            # Create local record
            payment_method = PaymentMethod.objects.create(
                customer=customer,
                stripe_payment_method_id=payment_method_id,
                type=pm.type,
                is_default=set_as_default,
                card_brand=pm.card.brand if pm.card else '',
                card_last4=pm.card.last4 if pm.card else '',
                card_exp_month=pm.card.exp_month if pm.card else None,
                card_exp_year=pm.card.exp_year if pm.card else None,
                card_funding=pm.card.funding if pm.card else '',
                billing_name=pm.billing_details.name or '',
                billing_email=pm.billing_details.email or '',
            )

            return payment_method

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error attaching payment method: {e}")
            raise

    def detach_payment_method(self, payment_method: PaymentMethod) -> bool:
        """Detach a payment method from customer."""
        try:
            stripe.PaymentMethod.detach(payment_method.stripe_payment_method_id)
            payment_method.delete()
            return True
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error detaching payment method: {e}")
            return False

    def list_payment_methods(self, customer: Customer) -> List[PaymentMethod]:
        """List all payment methods for a customer."""
        try:
            stripe_methods = stripe.PaymentMethod.list(
                customer=customer.stripe_customer_id,
                type='card'
            )

            # Sync with local records
            for pm in stripe_methods.data:
                PaymentMethod.objects.update_or_create(
                    stripe_payment_method_id=pm.id,
                    defaults={
                        'customer': customer,
                        'type': pm.type,
                        'card_brand': pm.card.brand if pm.card else '',
                        'card_last4': pm.card.last4 if pm.card else '',
                        'card_exp_month': pm.card.exp_month if pm.card else None,
                        'card_exp_year': pm.card.exp_year if pm.card else None,
                    }
                )

            return list(customer.payment_methods.all())

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error listing payment methods: {e}")
            return []

    # =========================================================================
    # Subscriptions
    # =========================================================================

    def create_subscription(
        self,
        customer: Customer,
        plan: SubscriptionPlan,
        billing_period: str = 'monthly',
        payment_method_id: str = None,
        coupon_code: str = None,
        trial_days: int = None
    ) -> Tuple[Subscription, Dict[str, Any]]:
        """
        Create a new subscription.

        Returns:
            Tuple of (Subscription, payment_info)
            payment_info contains client_secret if payment required
        """
        try:
            price_id = plan.get_stripe_price_id(billing_period)
            if not price_id:
                raise ValueError(f"No Stripe price configured for {plan.name} {billing_period}")

            # Build subscription params
            sub_params = {
                'customer': customer.stripe_customer_id,
                'items': [{'price': price_id}],
                'payment_behavior': 'default_incomplete',
                'payment_settings': {'save_default_payment_method': 'on_subscription'},
                'expand': ['latest_invoice.payment_intent'],
                'metadata': {
                    'plan_id': str(plan.id),
                    'plan_tier': plan.tier,
                }
            }

            # Add payment method if provided
            if payment_method_id:
                sub_params['default_payment_method'] = payment_method_id

            # Add coupon if provided
            if coupon_code:
                try:
                    coupon = Coupon.objects.get(code=coupon_code, valid=True)
                    if coupon.is_valid:
                        sub_params['coupon'] = coupon.stripe_coupon_id
                except Coupon.DoesNotExist:
                    pass

            # Add trial if specified
            if trial_days:
                sub_params['trial_period_days'] = trial_days

            # Create Stripe subscription
            stripe_sub = stripe.Subscription.create(**sub_params)

            # Create local subscription record
            subscription = Subscription.objects.create(
                customer=customer,
                plan=plan,
                stripe_subscription_id=stripe_sub.id,
                stripe_price_id=price_id,
                status=stripe_sub.status,
                billing_period=billing_period,
                current_period_start=datetime.fromtimestamp(
                    stripe_sub.current_period_start, tz=timezone.utc
                ),
                current_period_end=datetime.fromtimestamp(
                    stripe_sub.current_period_end, tz=timezone.utc
                ),
                cancel_at_period_end=stripe_sub.cancel_at_period_end,
            )

            # Handle trial
            if stripe_sub.trial_start:
                subscription.trial_start = datetime.fromtimestamp(
                    stripe_sub.trial_start, tz=timezone.utc
                )
            if stripe_sub.trial_end:
                subscription.trial_end = datetime.fromtimestamp(
                    stripe_sub.trial_end, tz=timezone.utc
                )
            subscription.save()

            # Update user plan
            customer.user.plan = plan.tier
            customer.user.save(update_fields=['plan'])

            # Prepare payment info
            payment_info = {'subscription_id': subscription.id}

            if stripe_sub.latest_invoice:
                invoice = stripe_sub.latest_invoice
                if hasattr(invoice, 'payment_intent') and invoice.payment_intent:
                    payment_info['client_secret'] = invoice.payment_intent.client_secret
                    payment_info['payment_intent_id'] = invoice.payment_intent.id
                    payment_info['payment_status'] = invoice.payment_intent.status

            logger.info(f"Created subscription: {stripe_sub.id} for {customer.email}")
            return subscription, payment_info

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription: {e}")
            raise

    def update_subscription(
        self,
        subscription: Subscription,
        new_plan: SubscriptionPlan = None,
        billing_period: str = None,
        proration_behavior: str = 'create_prorations'
    ) -> Subscription:
        """
        Update/upgrade subscription to new plan.

        Args:
            subscription: Current subscription
            new_plan: New plan to switch to
            billing_period: New billing period
            proration_behavior: How to handle prorations
        """
        try:
            update_params = {}

            if new_plan:
                price_id = new_plan.get_stripe_price_id(
                    billing_period or subscription.billing_period
                )

                # Get current subscription item
                stripe_sub = stripe.Subscription.retrieve(
                    subscription.stripe_subscription_id
                )

                update_params['items'] = [{
                    'id': stripe_sub['items']['data'][0].id,
                    'price': price_id,
                }]
                update_params['proration_behavior'] = proration_behavior

            # Update Stripe subscription
            stripe_sub = stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                **update_params
            )

            # Update local record
            if new_plan:
                subscription.plan = new_plan
                subscription.stripe_price_id = price_id
                subscription.customer.user.plan = new_plan.tier
                subscription.customer.user.save(update_fields=['plan'])

            if billing_period:
                subscription.billing_period = billing_period

            subscription.status = stripe_sub.status
            subscription.current_period_start = datetime.fromtimestamp(
                stripe_sub.current_period_start, tz=timezone.utc
            )
            subscription.current_period_end = datetime.fromtimestamp(
                stripe_sub.current_period_end, tz=timezone.utc
            )
            subscription.save()

            logger.info(f"Updated subscription: {subscription.stripe_subscription_id}")
            return subscription

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error updating subscription: {e}")
            raise

    def cancel_subscription(
        self,
        subscription: Subscription,
        immediately: bool = False,
        cancellation_reason: str = ''
    ) -> Subscription:
        """
        Cancel a subscription.

        Args:
            subscription: Subscription to cancel
            immediately: Cancel now or at period end
            cancellation_reason: Reason for cancellation
        """
        try:
            if immediately:
                stripe_sub = stripe.Subscription.delete(
                    subscription.stripe_subscription_id
                )
                subscription.status = 'canceled'
                subscription.canceled_at = timezone.now()
                subscription.ended_at = timezone.now()
            else:
                stripe_sub = stripe.Subscription.modify(
                    subscription.stripe_subscription_id,
                    cancel_at_period_end=True,
                    metadata={'cancellation_reason': cancellation_reason}
                )
                subscription.cancel_at_period_end = True
                subscription.canceled_at = timezone.now()

            subscription.save()

            # Downgrade user to free plan if canceled immediately
            if immediately:
                subscription.customer.user.plan = 'free'
                subscription.customer.user.save(update_fields=['plan'])

            logger.info(f"Canceled subscription: {subscription.stripe_subscription_id}")
            return subscription

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error canceling subscription: {e}")
            raise

    def reactivate_subscription(self, subscription: Subscription) -> Subscription:
        """Reactivate a subscription scheduled for cancellation."""
        try:
            if not subscription.cancel_at_period_end:
                return subscription

            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=False
            )

            subscription.cancel_at_period_end = False
            subscription.canceled_at = None
            subscription.save()

            logger.info(f"Reactivated subscription: {subscription.stripe_subscription_id}")
            return subscription

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error reactivating subscription: {e}")
            raise

    def get_subscription(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get subscription details from Stripe."""
        try:
            return stripe.Subscription.retrieve(subscription_id)
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error retrieving subscription: {e}")
            return None

    # =========================================================================
    # Invoices
    # =========================================================================

    def sync_invoice(self, stripe_invoice) -> Invoice:
        """Sync a Stripe invoice to local database."""
        try:
            customer = Customer.objects.get(
                stripe_customer_id=stripe_invoice.customer
            )
        except Customer.DoesNotExist:
            logger.warning(f"Customer not found for invoice: {stripe_invoice.id}")
            return None

        subscription = None
        if stripe_invoice.subscription:
            try:
                subscription = Subscription.objects.get(
                    stripe_subscription_id=stripe_invoice.subscription
                )
            except Subscription.DoesNotExist:
                pass

        invoice, _ = Invoice.objects.update_or_create(
            stripe_invoice_id=stripe_invoice.id,
            defaults={
                'customer': customer,
                'subscription': subscription,
                'status': stripe_invoice.status,
                'amount_due': stripe_invoice.amount_due,
                'amount_paid': stripe_invoice.amount_paid,
                'amount_remaining': stripe_invoice.amount_remaining,
                'subtotal': stripe_invoice.subtotal,
                'tax': stripe_invoice.tax or 0,
                'total': stripe_invoice.total,
                'currency': stripe_invoice.currency,
                'invoice_number': stripe_invoice.number or '',
                'invoice_pdf': stripe_invoice.invoice_pdf or '',
                'hosted_invoice_url': stripe_invoice.hosted_invoice_url or '',
                'period_start': datetime.fromtimestamp(
                    stripe_invoice.period_start, tz=timezone.utc
                ) if stripe_invoice.period_start else None,
                'period_end': datetime.fromtimestamp(
                    stripe_invoice.period_end, tz=timezone.utc
                ) if stripe_invoice.period_end else None,
                'due_date': datetime.fromtimestamp(
                    stripe_invoice.due_date, tz=timezone.utc
                ) if stripe_invoice.due_date else None,
                'lines': [
                    {
                        'description': line.description,
                        'amount': line.amount,
                        'quantity': line.quantity,
                    }
                    for line in stripe_invoice.lines.data
                ],
            }
        )

        return invoice

    def list_invoices(
        self,
        customer: Customer,
        limit: int = 10
    ) -> List[Invoice]:
        """List invoices for a customer."""
        try:
            stripe_invoices = stripe.Invoice.list(
                customer=customer.stripe_customer_id,
                limit=limit
            )

            # Sync to local database
            for stripe_inv in stripe_invoices.data:
                self.sync_invoice(stripe_inv)

            return list(customer.invoices.all()[:limit])

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error listing invoices: {e}")
            return []

    def get_upcoming_invoice(self, customer: Customer) -> Optional[Dict[str, Any]]:
        """Get upcoming invoice for customer."""
        try:
            upcoming = stripe.Invoice.upcoming(
                customer=customer.stripe_customer_id
            )
            return {
                'amount_due': upcoming.amount_due,
                'total': upcoming.total,
                'currency': upcoming.currency,
                'period_start': upcoming.period_start,
                'period_end': upcoming.period_end,
                'lines': [
                    {
                        'description': line.description,
                        'amount': line.amount,
                    }
                    for line in upcoming.lines.data
                ]
            }
        except stripe.error.InvalidRequestError:
            # No upcoming invoice (free plan or no subscription)
            return None
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error getting upcoming invoice: {e}")
            return None

    # =========================================================================
    # Checkout Sessions
    # =========================================================================

    def create_checkout_session(
        self,
        customer: Customer,
        plan: SubscriptionPlan,
        billing_period: str = 'monthly',
        success_url: str = None,
        cancel_url: str = None,
        coupon_code: str = None
    ) -> Dict[str, Any]:
        """
        Create a Stripe Checkout session for subscription.

        Returns session URL for redirect.
        """
        try:
            price_id = plan.get_stripe_price_id(billing_period)

            session_params = {
                'customer': customer.stripe_customer_id,
                'mode': 'subscription',
                'line_items': [{'price': price_id, 'quantity': 1}],
                'success_url': success_url or settings.STRIPE_SUCCESS_URL,
                'cancel_url': cancel_url or settings.STRIPE_CANCEL_URL,
                'metadata': {
                    'plan_id': str(plan.id),
                    'customer_id': str(customer.id),
                },
                'subscription_data': {
                    'metadata': {
                        'plan_tier': plan.tier,
                    }
                },
                'allow_promotion_codes': True,
            }

            # Add specific coupon if provided
            if coupon_code:
                try:
                    coupon = Coupon.objects.get(code=coupon_code, valid=True)
                    if coupon.is_valid:
                        session_params['discounts'] = [{'coupon': coupon.stripe_coupon_id}]
                        session_params['allow_promotion_codes'] = False
                except Coupon.DoesNotExist:
                    pass

            session = stripe.checkout.Session.create(**session_params)

            return {
                'session_id': session.id,
                'url': session.url,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating checkout session: {e}")
            raise

    def create_billing_portal_session(
        self,
        customer: Customer,
        return_url: str = None
    ) -> Dict[str, Any]:
        """
        Create a Stripe Customer Portal session.

        Allows customers to manage subscriptions, payment methods, etc.
        """
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer.stripe_customer_id,
                return_url=return_url or settings.STRIPE_PORTAL_RETURN_URL,
            )

            return {
                'url': session.url,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating portal session: {e}")
            raise

    # =========================================================================
    # Usage-Based Billing
    # =========================================================================

    def record_usage(
        self,
        customer: Customer,
        usage_type: str,
        quantity: int = 1,
        request_id: str = '',
        endpoint: str = '',
        metadata: Dict[str, Any] = None
    ) -> UsageRecord:
        """
        Record API usage for a customer.

        Args:
            customer: Customer making the request
            usage_type: Type of usage (message_analysis, url_analysis, etc.)
            quantity: Number of units
            request_id: Request identifier
            endpoint: API endpoint called
            metadata: Additional metadata
        """
        now = timezone.now()
        today = now.date()

        # Get current subscription if any
        subscription = customer.subscriptions.filter(
            status__in=['active', 'trialing']
        ).first()

        # Determine billing period
        if subscription:
            period_start = subscription.current_period_start.date()
            period_end = subscription.current_period_end.date()
        else:
            # For free tier, use calendar month
            period_start = today.replace(day=1)
            if today.month == 12:
                period_end = today.replace(year=today.year + 1, month=1, day=1)
            else:
                period_end = today.replace(month=today.month + 1, day=1)

        # Create usage record
        usage_record = UsageRecord.objects.create(
            customer=customer,
            subscription=subscription,
            usage_type=usage_type,
            quantity=quantity,
            request_id=request_id,
            endpoint=endpoint,
            timestamp=now,
            billing_period_start=period_start,
            billing_period_end=period_end,
            metadata=metadata or {}
        )

        # Update daily summary
        self._update_usage_summary(customer, today, usage_type, quantity)

        # Report to Stripe if metered billing is enabled
        # This would be implemented for usage-based pricing
        # if subscription and subscription.plan.is_metered:
        #     self._report_usage_to_stripe(subscription, quantity)

        return usage_record

    def _update_usage_summary(
        self,
        customer: Customer,
        date,
        usage_type: str,
        quantity: int
    ):
        """Update daily and monthly usage summaries."""
        # Get or create daily summary
        daily_summary, _ = UsageSummary.objects.get_or_create(
            customer=customer,
            period_type='daily',
            period_start=date,
            defaults={
                'period_end': date,
                'daily_limit': self._get_daily_limit(customer),
                'monthly_limit': self._get_monthly_limit(customer),
            }
        )

        # Update daily counts
        self._increment_usage_count(daily_summary, usage_type, quantity)

        # Get or create monthly summary
        month_start = date.replace(day=1)
        if date.month == 12:
            month_end = date.replace(year=date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = date.replace(month=date.month + 1, day=1) - timedelta(days=1)

        monthly_summary, _ = UsageSummary.objects.get_or_create(
            customer=customer,
            period_type='monthly',
            period_start=month_start,
            defaults={
                'period_end': month_end,
                'daily_limit': self._get_daily_limit(customer),
                'monthly_limit': self._get_monthly_limit(customer),
            }
        )

        # Update monthly counts
        self._increment_usage_count(monthly_summary, usage_type, quantity)

    def _increment_usage_count(self, summary: UsageSummary, usage_type: str, quantity: int):
        """Increment usage count on a summary."""
        field_map = {
            'message_analysis': 'message_analyses',
            'url_analysis': 'url_analyses',
            'phone_analysis': 'phone_analyses',
            'image_analysis': 'image_analyses',
            'batch_analysis': 'batch_analyses',
        }

        field = field_map.get(usage_type)
        if field:
            setattr(summary, field, getattr(summary, field) + quantity)

        summary.total_requests += quantity

        # Check if limit reached
        if summary.period_type == 'daily':
            summary.limit_reached = summary.total_requests >= summary.daily_limit
        else:
            summary.limit_reached = summary.total_requests >= summary.monthly_limit

        summary.save()

    def _get_daily_limit(self, customer: Customer) -> int:
        """Get daily request limit for customer."""
        subscription = customer.subscriptions.filter(
            status__in=['active', 'trialing']
        ).first()

        if subscription:
            return subscription.plan.daily_request_limit

        # Free tier default
        return getattr(settings, 'FREE_DAILY_LIMIT', 10)

    def _get_monthly_limit(self, customer: Customer) -> int:
        """Get monthly request limit for customer."""
        subscription = customer.subscriptions.filter(
            status__in=['active', 'trialing']
        ).first()

        if subscription:
            return subscription.plan.monthly_request_limit

        # Free tier default
        return getattr(settings, 'FREE_MONTHLY_LIMIT', 100)

    def check_usage_limit(self, customer: Customer) -> Dict[str, Any]:
        """
        Check if customer has exceeded usage limits.

        Returns:
            Dict with limit info and whether requests are allowed
        """
        today = timezone.now().date()

        # Get daily summary
        try:
            daily = UsageSummary.objects.get(
                customer=customer,
                period_type='daily',
                period_start=today
            )
            daily_used = daily.total_requests
            daily_limit = daily.daily_limit
        except UsageSummary.DoesNotExist:
            daily_used = 0
            daily_limit = self._get_daily_limit(customer)

        # Get monthly summary
        month_start = today.replace(day=1)
        try:
            monthly = UsageSummary.objects.get(
                customer=customer,
                period_type='monthly',
                period_start=month_start
            )
            monthly_used = monthly.total_requests
            monthly_limit = monthly.monthly_limit
        except UsageSummary.DoesNotExist:
            monthly_used = 0
            monthly_limit = self._get_monthly_limit(customer)

        # Determine if allowed
        daily_exceeded = daily_used >= daily_limit
        monthly_exceeded = monthly_used >= monthly_limit
        allowed = not (daily_exceeded or monthly_exceeded)

        return {
            'allowed': allowed,
            'daily': {
                'used': daily_used,
                'limit': daily_limit,
                'remaining': max(0, daily_limit - daily_used),
                'exceeded': daily_exceeded,
            },
            'monthly': {
                'used': monthly_used,
                'limit': monthly_limit,
                'remaining': max(0, monthly_limit - monthly_used),
                'exceeded': monthly_exceeded,
            },
            'upgrade_required': not allowed,
        }

    def get_usage_stats(
        self,
        customer: Customer,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get usage statistics for customer."""
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)

        # Get daily summaries
        daily_summaries = UsageSummary.objects.filter(
            customer=customer,
            period_type='daily',
            period_start__gte=start_date,
            period_start__lte=end_date
        ).order_by('period_start')

        # Build daily stats
        daily_stats = []
        for summary in daily_summaries:
            daily_stats.append({
                'date': summary.period_start.isoformat(),
                'total': summary.total_requests,
                'message': summary.message_analyses,
                'url': summary.url_analyses,
                'phone': summary.phone_analyses,
                'image': summary.image_analyses,
            })

        # Calculate totals
        totals = UsageRecord.objects.filter(
            customer=customer,
            timestamp__date__gte=start_date,
            timestamp__date__lte=end_date
        ).values('usage_type').annotate(
            count=models.Sum('quantity')
        )

        totals_dict = {t['usage_type']: t['count'] for t in totals}

        return {
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': days,
            },
            'daily': daily_stats,
            'totals': {
                'message_analyses': totals_dict.get('message_analysis', 0),
                'url_analyses': totals_dict.get('url_analysis', 0),
                'phone_analyses': totals_dict.get('phone_analysis', 0),
                'image_analyses': totals_dict.get('image_analysis', 0),
                'total': sum(totals_dict.values()),
            },
            'current_limits': self.check_usage_limit(customer),
        }


# Singleton instance
stripe_service = StripeService()
