"""
Billing App Configuration.
"""

from django.apps import AppConfig


class BillingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.billing'
    verbose_name = 'Billing & Subscriptions'

    def ready(self):
        """Initialize app when Django starts."""
        # Import signals if needed
        # from . import signals
        pass
