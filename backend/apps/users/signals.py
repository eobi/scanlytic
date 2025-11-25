"""
Signals for User app.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User, APIKey


@receiver(post_save, sender=User)
def create_default_api_key(sender, instance, created, **kwargs):
    """Create a default API key for new users."""
    if created:
        # Only create if no keys exist
        if not instance.api_keys.exists():
            APIKey.objects.create(
                user=instance,
                name='Default Key'
            )
