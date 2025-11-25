"""
URL patterns for Analysis API.
"""

from django.urls import path

from .views import (
    MessageAnalysisView, URLAnalysisView, PhoneAnalysisView,
    ProfileAnalysisView, AnalysisHistoryView, AnalysisDetailView,
    ScamReportListCreateView, QuickScanView, BatchAnalysisView
)

app_name = 'analysis'

urlpatterns = [
    # Main analysis endpoints
    path('message/', MessageAnalysisView.as_view(), name='message-analysis'),
    path('url/', URLAnalysisView.as_view(), name='url-analysis'),
    path('phone/', PhoneAnalysisView.as_view(), name='phone-analysis'),
    path('profile/', ProfileAnalysisView.as_view(), name='profile-analysis'),

    # Quick scan (limited, can be anonymous)
    path('quick/', QuickScanView.as_view(), name='quick-scan'),

    # Batch analysis
    path('batch/', BatchAnalysisView.as_view(), name='batch-analysis'),

    # History and details
    path('history/', AnalysisHistoryView.as_view(), name='analysis-history'),
    path('<str:request_id>/', AnalysisDetailView.as_view(), name='analysis-detail'),

    # Scam reports
    path('reports/', ScamReportListCreateView.as_view(), name='scam-reports'),
]
