import logging

logger = logging.getLogger(__name__)


def check_env(env):
    if "SERVICE_TOKEN" not in env:
        logger.error("SERVICE_TOKEN is not set; the token must be provided")
