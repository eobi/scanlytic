"""
Celery configuration for Scamlytic API.

Handles async task processing for:
- Deep URL analysis
- Image reverse search
- Report generation
- Bulk scanning operations
"""

import os

from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scamlytic.settings')

app = Celery('scamlytic')

# Load config from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all installed apps
app.autodiscover_tasks()

# Celery Beat Schedule (Periodic Tasks)
app.conf.beat_schedule = {
    # Update threat intelligence databases daily
    'update-threat-databases': {
        'task': 'apps.integrations.tasks.update_threat_databases',
        'schedule': crontab(hour=2, minute=0),  # 2 AM daily
    },
    # Clean up old analysis records
    'cleanup-old-records': {
        'task': 'apps.analysis.tasks.cleanup_old_records',
        'schedule': crontab(hour=3, minute=0),  # 3 AM daily
    },
    # Sync PhishTank database
    'sync-phishtank': {
        'task': 'apps.integrations.tasks.sync_phishtank_database',
        'schedule': crontab(hour=4, minute=0),  # 4 AM daily
    },
    # Generate usage reports
    'generate-usage-reports': {
        'task': 'apps.reports.tasks.generate_daily_usage_reports',
        'schedule': crontab(hour=0, minute=30),  # 12:30 AM daily
    },
    # Health check integrations
    'health-check-integrations': {
        'task': 'apps.integrations.tasks.health_check_all_integrations',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
    },
}


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')
