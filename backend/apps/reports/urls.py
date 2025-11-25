"""
URL patterns for Reports API.
"""

from django.urls import path

from .views import (
    ReportListCreateView, ReportDetailView, ReportDownloadView,
    SharedReportView, ScheduledReportListCreateView, ScheduledReportDetailView
)

app_name = 'reports'

urlpatterns = [
    # Reports
    path('', ReportListCreateView.as_view(), name='report-list'),
    path('<uuid:pk>/', ReportDetailView.as_view(), name='report-detail'),
    path('<uuid:pk>/download/', ReportDownloadView.as_view(), name='report-download'),

    # Shared reports (public)
    path('shared/<str:token>/', SharedReportView.as_view(), name='shared-report'),

    # Scheduled reports
    path('scheduled/', ScheduledReportListCreateView.as_view(), name='scheduled-list'),
    path('scheduled/<uuid:pk>/', ScheduledReportDetailView.as_view(), name='scheduled-detail'),
]
