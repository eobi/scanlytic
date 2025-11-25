"""
Celery tasks for integrations.
"""

from celery import shared_task
import logging

logger = logging.getLogger('scamlytic.integrations.tasks')


@shared_task
def update_threat_databases():
    """Update threat intelligence databases."""
    logger.info("Updating threat databases...")
    # Implementation would sync with external threat feeds
    pass


@shared_task
def sync_phishtank_database():
    """Sync PhishTank database."""
    logger.info("Syncing PhishTank database...")
    # Implementation would download and process PhishTank data
    pass


@shared_task
def health_check_all_integrations():
    """Check health of all external integrations."""
    from .services import IntegrationHealthService

    logger.info("Running integration health checks...")
    service = IntegrationHealthService()
    results = service.check_all()

    unhealthy = [k for k, v in results.items() if not v.get('is_healthy')]
    if unhealthy:
        logger.warning(f"Unhealthy integrations: {unhealthy}")
    else:
        logger.info("All integrations healthy")

    return results
