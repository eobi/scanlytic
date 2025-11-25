"""
Billing URL Configuration.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    SubscriptionPlanViewSet, CustomerViewSet, SubscriptionViewSet,
    PaymentMethodViewSet, InvoiceViewSet, UsageViewSet, CouponViewSet,
    CheckoutView, BillingPortalView, StripeConfigView,
)
from .webhooks import stripe_webhook

app_name = 'billing'

# Create router for viewsets
router = DefaultRouter()
router.register(r'plans', SubscriptionPlanViewSet, basename='plan')
router.register(r'invoices', InvoiceViewSet, basename='invoice')

urlpatterns = [
    # Viewset routes
    path('', include(router.urls)),

    # Customer endpoints
    path('customer/', CustomerViewSet.as_view({
        'get': 'retrieve',
    }), name='customer-detail'),
    path('customer/update/', CustomerViewSet.as_view({
        'patch': 'update_profile',
    }), name='customer-update'),

    # Subscription endpoints
    path('subscriptions/', SubscriptionViewSet.as_view({
        'get': 'list',
        'post': 'create',
    }), name='subscription-list'),
    path('subscriptions/current/', SubscriptionViewSet.as_view({
        'get': 'current',
    }), name='subscription-current'),
    path('subscriptions/<uuid:pk>/', SubscriptionViewSet.as_view({
        'get': 'retrieve',
    }), name='subscription-detail'),
    path('subscriptions/<uuid:pk>/update/', SubscriptionViewSet.as_view({
        'patch': 'update_plan',
    }), name='subscription-update'),
    path('subscriptions/<uuid:pk>/cancel/', SubscriptionViewSet.as_view({
        'post': 'cancel',
    }), name='subscription-cancel'),
    path('subscriptions/<uuid:pk>/reactivate/', SubscriptionViewSet.as_view({
        'post': 'reactivate',
    }), name='subscription-reactivate'),

    # Payment method endpoints
    path('payment-methods/', PaymentMethodViewSet.as_view({
        'get': 'list',
    }), name='payment-method-list'),
    path('payment-methods/setup/', PaymentMethodViewSet.as_view({
        'post': 'setup_intent',
    }), name='payment-method-setup'),
    path('payment-methods/attach/', PaymentMethodViewSet.as_view({
        'post': 'attach',
    }), name='payment-method-attach'),
    path('payment-methods/<uuid:pk>/detach/', PaymentMethodViewSet.as_view({
        'delete': 'detach',
    }), name='payment-method-detach'),

    # Invoice endpoints
    path('invoices/upcoming/', InvoiceViewSet.as_view({
        'get': 'upcoming',
    }), name='invoice-upcoming'),

    # Usage endpoints
    path('usage/limits/', UsageViewSet.as_view({
        'get': 'limits',
    }), name='usage-limits'),
    path('usage/stats/', UsageViewSet.as_view({
        'get': 'stats',
    }), name='usage-stats'),
    path('usage/summary/', UsageViewSet.as_view({
        'get': 'summary',
    }), name='usage-summary'),

    # Coupon validation
    path('coupons/validate/', CouponViewSet.as_view({
        'post': 'validate',
    }), name='coupon-validate'),

    # Checkout and portal
    path('checkout/', CheckoutView.as_view(), name='checkout'),
    path('portal/', BillingPortalView.as_view(), name='portal'),

    # Stripe config (public)
    path('config/', StripeConfigView.as_view(), name='config'),

    # Webhook
    path('webhook/', stripe_webhook, name='webhook'),
]
