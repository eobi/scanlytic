"""
Views for User management.
"""

from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login

from .models import User, APIKey, UserActivity, Subscription
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserSerializer,
    UserUpdateSerializer, PasswordChangeSerializer,
    APIKeySerializer, APIKeyCreateSerializer,
    UserActivitySerializer, SubscriptionSerializer, UsageStatsSerializer
)


class UserRegistrationView(generics.CreateAPIView):
    """
    Register a new user account.
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        # Create default API key
        api_key = APIKey.objects.create(
            user=user,
            name='Default Key'
        )

        # Log activity
        UserActivity.objects.create(
            user=user,
            action='login',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'api_key': api_key.key,
        }, status=status.HTTP_201_CREATED)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class UserLoginView(views.APIView):
    """
    Login with email and password to get JWT tokens.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        # Log activity
        UserActivity.objects.create(
            user=user,
            action='login',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
        })

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Get or update user profile.
    """
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return UserSerializer
        return UserUpdateSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            action='profile_updated',
            ip_address=self._get_client_ip(request),
            metadata={'fields': list(request.data.keys())}
        )

        return response

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class PasswordChangeView(views.APIView):
    """
    Change user password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        # Update password
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            action='password_changed',
            ip_address=self._get_client_ip(request)
        )

        return Response({'message': 'Password changed successfully'})

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class UsageStatsView(views.APIView):
    """
    Get user's usage statistics.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user._reset_daily_count_if_needed()

        data = {
            'plan': user.plan,
            'daily_limit': user.daily_limit,
            'daily_used': user.daily_request_count,
            'daily_remaining': user.remaining_requests,
            'monthly_used': user.monthly_request_count,
            'total_used': user.total_request_count,
            'plan_expires_at': user.plan_expires_at,
            'is_plan_active': user.is_plan_active,
        }

        serializer = UsageStatsSerializer(data)
        return Response(serializer.data)


class APIKeyListCreateView(generics.ListCreateAPIView):
    """
    List user's API keys or create a new one.
    """
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return APIKeyCreateSerializer
        return APIKeySerializer

    def get_queryset(self):
        return APIKey.objects.filter(user=self.request.user, is_active=True)

    def create(self, request, *args, **kwargs):
        # Check API key limit
        key_count = APIKey.objects.filter(user=request.user, is_active=True).count()
        max_keys = {'free': 1, 'pro': 3, 'developer': 10, 'business': 50, 'enterprise': 100}
        if key_count >= max_keys.get(request.user.plan, 1):
            return Response(
                {'error': 'Maximum API keys reached for your plan'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        api_key = serializer.save()

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            action='key_created',
            ip_address=self._get_client_ip(request),
            metadata={'key_id': str(api_key.id), 'key_name': api_key.name}
        )

        # Return full key only on creation
        return Response({
            'id': api_key.id,
            'name': api_key.name,
            'key': api_key.key,  # Only shown once!
            'created_at': api_key.created_at,
            'message': 'Save this key securely. It will not be shown again.'
        }, status=status.HTTP_201_CREATED)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class APIKeyDetailView(generics.RetrieveDestroyAPIView):
    """
    Get or revoke an API key.
    """
    serializer_class = APIKeySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return APIKey.objects.filter(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        api_key = self.get_object()
        api_key.revoke()

        # Log activity
        UserActivity.objects.create(
            user=request.user,
            action='key_revoked',
            ip_address=self._get_client_ip(request),
            metadata={'key_id': str(api_key.id), 'key_name': api_key.name}
        )

        return Response({'message': 'API key revoked'}, status=status.HTTP_200_OK)

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class UserActivityListView(generics.ListAPIView):
    """
    List user's activity logs.
    """
    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserActivity.objects.filter(user=self.request.user)[:100]


class SubscriptionListView(generics.ListAPIView):
    """
    List user's subscriptions.
    """
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Subscription.objects.filter(user=self.request.user)
