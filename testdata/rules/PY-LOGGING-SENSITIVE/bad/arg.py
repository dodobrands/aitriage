import logging

logger = logging.getLogger(__name__)


def login(user, password):
    # ruleid: PY-LOGGING-SENSITIVE
    logger.info("login attempt user=%s password=%s", user, password)
