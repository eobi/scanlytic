"""
Billing API Views.

Provides endpoints for subscription management, payment methods,
invoices, and usage tracking.
"""

import logging
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

from .models import (
    SubscriptionPlan, Customer, Subscription, Invoice,
    PaymentMethod, UsageSummary, Coupon
)
from .serializers import (
    SubscriptionPlanSerializer, CustomerSerializer, CustomerUpdateSerializer,
    SubscriptionSerializer, CreateSubscriptionSerializer,
    UpdateSubscriptionSerializer, CancelSubscriptionSerializer,
    InvoiceSerializer, PaymentMethodSerializer,
    UsageSummarySerializer, UsageLimitsSerializer, UsageStatsSerializer,
    CouponSerializer, ValidateCouponSerializer,
    CheckoutSessionSerializer, BillingPortalSerializer,
    SetupIntentSerializer, AttachPaymentMethodSerializer,
)
from .stripe_service import stripe_service

logger = logging.getLogger('scamlytic.billing.views')


class SubscriptionPlanViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for listing subscription plans.

    list:
    Return all active subscription plans.

    retrieve:
    Return a specific plan by ID.
    """
    queryset = SubscriptionPlan.objects.filter(is_active=True)
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'id'

    @action(detail=False, methods=['get'])
    def by_tier(self, request):
        """Get plans organized by tier."""
        plans = self.get_queryset()
        plans_by_tier = {}
        for plan in plans:
            plans_by_tier[plan.tier] = SubscriptionPlanSerializer(plan).data
        return Response(plans_by_tier)


class CustomerViewSet(viewsets.ViewSet):
    """
    ViewSet for customer management.
    """
    permission_classes = [permissions.IsAuthenticated]

    def retrieve(self, request):
        """Get current user's customer profile."""
        try:
            customer = stripe_service.get_or_create_customer(request.user)
            serializer = CustomerSerializer(customer)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error getting customer: {e}")
            return Response(
                {'error': 'Failed to retrieve customer'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['patch'])
    def update_profile(self, request):
        """Update customer billing profile."""
        serializer = CustomerUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = stripe_service.get_or_create_customer(request.user)
            customer = stripe_service.update_customer(
                customer,
                **serializer.validated_data
            )
            return Response(CustomerSerializer(customer).data)
        except Exception as e:
            logger.error(f"Error updating customer: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class SubscriptionViewSet(viewsets.ViewSet):
    """
    ViewSet for subscription management.
    """
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        """List user's subscriptions."""
        try:
            customer = Customer.objects.get(user=request.user)
            subscriptions = customer.subscriptions.all()
            serializer = SubscriptionSerializer(subscriptions, many=True)
            return Response(serializer.data)
        except Customer.DoesNotExist:
            return Response([])

    def retrieve(self, request, pk=None):
        """Get specific subscription details."""
        try:
            customer = Customer.objects.get(user=request.user)
            subscription = get_object_or_404(
                customer.subscriptions, id=pk
            )
            serializer = SubscriptionSerializer(subscription)
            return Response(serializer.data)
        except Customer.DoesNotExist:
            return Response(
                {'error': 'No billing account found'},
                status=status.HTTP_404_NOT_FOUND
            )

    def create(self, request):
        """Create a new subscription."""
        serializer = CreateSubscriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = stripe_service.get_or_create_customer(request.user)

            subscription, payment_info = stripe_service.create_subscription(
                customer=customer,
                plan=serializer.validated_data['plan_id'],
                billing_period=serializer.validated_data.get('billing_period', 'monthly'),
                payment_method_id=serializer.validated_data.get('payment_method_id'),
                coupon_code=serializer.validated_data.get('coupon_code'),
            )

            response_data = SubscriptionSerializer(subscription).data
            response_data['payment_info'] = payment_info

            return Response(response_data, status=status.HTTP_201_CREATED)

        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error creating subscription: {e}")
            return Response(
                {'error': 'Failed to create subscription'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['patch'])
    def update_plan(self, request, pk=None):
        """Upgrade or downgrade subscription plan."""
        serializer = UpdateSubscriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = Customer.objects.get(user=request.user)
            subscription = get_object_or_404(customer.subscriptions, id=pk)

            subscription = stripe_service.update_subscription(
                subscription=subscription,
                new_plan=serializer.validated_data.get('plan_id'),
                billing_period=serializer.validated_data.get('billing_period'),
            )

            return Response(SubscriptionSerializer(subscription).data)

        except Exception as e:
            logger.error(f"Error updating subscription: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel subscription."""
        serializer = CancelSubscriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = Customer.objects.get(user=request.user)
            subscription = get_object_or_404(customer.subscriptions, id=pk)

            subscription = stripe_service.cancel_subscription(
                subscription=subscription,
                immediately=serializer.validated_data.get('immediately', False),
                cancellation_reason=serializer.validated_data.get('reason', ''),
            )

            return Response(SubscriptionSerializer(subscription).data)

        except Exception as e:
            logger.error(f"Error canceling subscription: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def reactivate(self, request, pk=None):
        """Reactivate a canceled subscription."""
        try:
            customer = Customer.objects.get(user=request.user)
            subscription = get_object_or_404(customer.subscriptions, id=pk)

            subscription = stripe_service.reactivate_subscription(subscription)
            return Response(SubscriptionSerializer(subscription).data)

        except Exception as e:
            logger.error(f"Error reactivating subscription: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'])
    def current(self, request):
        """Get current active subscription."""
        try:
            customer = Customer.objects.get(user=request.user)
            subscription = customer.subscriptions.filter(
                status__in=['active', 'trialing']
            ).first()

            if subscription:
                return Response(SubscriptionSerializer(subscription).data)
            return Response({'message': 'No active subscription'})

        except Customer.DoesNotExist:
            return Response({'message': 'No billing account'})


class PaymentMethodViewSet(viewsets.ViewSet):
    """
    ViewSet for payment method management.
    """
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        """List payment methods."""
        try:
            customer = stripe_service.get_or_create_customer(request.user)
            methods = stripe_service.list_payment_methods(customer)
            serializer = PaymentMethodSerializer(methods, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error listing payment methods: {e}")
            return Response(
                {'error': 'Failed to list payment methods'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def setup_intent(self, request):
        """Create a setup intent for adding new payment method."""
        try:
            customer = stripe_service.get_or_create_customer(request.user)
            result = stripe_service.create_setup_intent(customer)
            return Response(result)
        except Exception as e:
            logger.error(f"Error creating setup intent: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'])
    def attach(self, request):
        """Attach a payment method to customer."""
        serializer = AttachPaymentMethodSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = stripe_service.get_or_create_customer(request.user)
            payment_method = stripe_service.attach_payment_method(
                customer=customer,
                payment_method_id=serializer.validated_data['payment_method_id'],
                set_as_default=serializer.validated_data.get('set_as_default', True),
            )
            return Response(PaymentMethodSerializer(payment_method).data)
        except Exception as e:
            logger.error(f"Error attaching payment method: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['delete'])
    def detach(self, request, pk=None):
        """Detach/remove a payment method."""
        try:
            customer = Customer.objects.get(user=request.user)
            payment_method = get_object_or_404(customer.payment_methods, id=pk)

            success = stripe_service.detach_payment_method(payment_method)
            if success:
                return Response(status=status.HTTP_204_NO_CONTENT)
            return Response(
                {'error': 'Failed to remove payment method'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Customer.DoesNotExist:
            return Response(
                {'error': 'No billing account found'},
                status=status.HTTP_404_NOT_FOUND
            )


class InvoiceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for invoice management.
    """
    serializer_class = InvoiceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        try:
            customer = Customer.objects.get(user=self.request.user)
            return customer.invoices.all()
        except Customer.DoesNotExist:
            return Invoice.objects.none()

    @action(detail=False, methods=['get'])
    def upcoming(self, request):
        """Get upcoming invoice."""
        try:
            customer = Customer.objects.get(user=request.user)
            upcoming = stripe_service.get_upcoming_invoice(customer)
            if upcoming:
                return Response(upcoming)
            return Response({'message': 'No upcoming invoice'})
        except Customer.DoesNotExist:
            return Response({'message': 'No billing account'})


class UsageViewSet(viewsets.ViewSet):
    """
    ViewSet for usage tracking and limits.
    """
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def limits(self, request):
        """Check current usage limits."""
        try:
            customer = stripe_service.get_or_create_customer(request.user)
            limits = stripe_service.check_usage_limit(customer)
            return Response(limits)
        except Exception as e:
            logger.error(f"Error checking usage limits: {e}")
            return Response(
                {'error': 'Failed to check limits'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get usage statistics."""
        days = int(request.query_params.get('days', 30))
        days = min(max(days, 1), 365)  # Clamp between 1-365

        try:
            customer = stripe_service.get_or_create_customer(request.user)
            stats = stripe_service.get_usage_stats(customer, days=days)
            return Response(stats)
        except Exception as e:
            logger.error(f"Error getting usage stats: {e}")
            return Response(
                {'error': 'Failed to get usage stats'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get current period summary."""
        try:
            customer = Customer.objects.get(user=request.user)

            # Get today's and this month's summary
            from django.utils import timezone
            today = timezone.now().date()
            month_start = today.replace(day=1)

            daily = UsageSummary.objects.filter(
                customer=customer,
                period_type='daily',
                period_start=today
            ).first()

            monthly = UsageSummary.objects.filter(
                customer=customer,
                period_type='monthly',
                period_start=month_start
            ).first()

            return Response({
                'daily': UsageSummarySerializer(daily).data if daily else None,
                'monthly': UsageSummarySerializer(monthly).data if monthly else None,
            })

        except Customer.DoesNotExist:
            return Response({'daily': None, 'monthly': None})


class CouponViewSet(viewsets.ViewSet):
    """
    ViewSet for coupon validation.
    """
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['post'])
    def validate(self, request):
        """Validate a coupon code."""
        serializer = ValidateCouponSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            coupon = Coupon.objects.get(
                code=serializer.validated_data['code'],
                valid=True
            )

            if not coupon.is_valid:
                return Response(
                    {'valid': False, 'message': 'Coupon has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if applies to specific plan
            plan_id = serializer.validated_data.get('plan_id')
            if plan_id and coupon.applies_to_plans.exists():
                if not coupon.applies_to_plans.filter(id=plan_id).exists():
                    return Response(
                        {'valid': False, 'message': 'Coupon not valid for this plan'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            return Response({
                'valid': True,
                'coupon': CouponSerializer(coupon).data,
            })

        except Coupon.DoesNotExist:
            return Response(
                {'valid': False, 'message': 'Invalid coupon code'},
                status=status.HTTP_400_BAD_REQUEST
            )


class CheckoutView(APIView):
    """
    Create Stripe Checkout session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = CheckoutSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = stripe_service.get_or_create_customer(request.user)
            result = stripe_service.create_checkout_session(
                customer=customer,
                plan=serializer.validated_data['plan_id'],
                billing_period=serializer.validated_data.get('billing_period', 'monthly'),
                success_url=serializer.validated_data.get('success_url'),
                cancel_url=serializer.validated_data.get('cancel_url'),
                coupon_code=serializer.validated_data.get('coupon_code'),
            )
            return Response(result)

        except Exception as e:
            logger.error(f"Error creating checkout session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class BillingPortalView(APIView):
    """
    Create Stripe Billing Portal session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = BillingPortalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            customer = stripe_service.get_or_create_customer(request.user)
            result = stripe_service.create_billing_portal_session(
                customer=customer,
                return_url=serializer.validated_data.get('return_url'),
            )
            return Response(result)

        except Exception as e:
            logger.error(f"Error creating billing portal session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class StripeConfigView(APIView):
    """
    Get Stripe publishable key for frontend.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({
            'publishable_key': stripe_service.publishable_key,
            'configured': stripe_service.is_configured(),
        })
