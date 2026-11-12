import logging

logger = logging.getLogger(__name__)


def show(token):
    logger.info("using token ending %s", mask(token))
    logger.debug(f"token length {len(token)}")
