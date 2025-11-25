"""
URL patterns for User management.
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    UserRegistrationView, UserLoginView, UserProfileView,
    PasswordChangeView, UsageStatsView,
    APIKeyListCreateView, APIKeyDetailView,
    UserActivityListView, SubscriptionListView
)

app_name = 'users'

urlpatterns = [
    # Authentication
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),

    # Profile
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('password/', PasswordChangeView.as_view(), name='password-change'),
    path('usage/', UsageStatsView.as_view(), name='usage-stats'),

    # API Keys
    path('api-keys/', APIKeyListCreateView.as_view(), name='api-key-list'),
    path('api-keys/<uuid:pk>/', APIKeyDetailView.as_view(), name='api-key-detail'),

    # Activity & Subscriptions
    path('activity/', UserActivityListView.as_view(), name='activity-list'),
    path('subscriptions/', SubscriptionListView.as_view(), name='subscription-list'),
]
