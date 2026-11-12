import structlog

logger = structlog.get_logger()


def reset(user, reset_token):
    # ruleid: PY-LOGGING-SENSITIVE
    logger.info("password reset issued", user=user.id, token=reset_token)
