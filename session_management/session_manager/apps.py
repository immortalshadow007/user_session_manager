from django.apps import AppConfig
import logging as log

logger = log.getLogger(__name__)

class SessionManagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'session_manager'

    # Any startup task for the totp_services app can be included here
    def ready(self):
        logger.info('session_manager app is ready')
