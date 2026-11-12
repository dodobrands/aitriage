import logging

logger = logging.getLogger(__name__)


def refresh(session):
    # ruleid: PY-LOGGING-SENSITIVE
    logger.debug(f"refreshed session, new token={session.access_token}")
