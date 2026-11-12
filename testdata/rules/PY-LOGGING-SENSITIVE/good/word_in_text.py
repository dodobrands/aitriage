import logging

logger = logging.getLogger(__name__)


def on_expired(user_id):
    logger.warning("Access token missing in callback for user %s", user_id)
    logger.info("password reset requested for %s", user_id)
    logger.error("Fields required (username, password)")
